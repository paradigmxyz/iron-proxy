package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// buildMITMPassthroughProxy builds a mitm-mode proxy (allowlist permitting
// localhost and allowed.example) whose tls.passthrough_hosts is the given list.
// Returns the tunnel address, the proxy CA pool and the audit accessor.
func buildMITMPassthroughProxy(t *testing.T, passthrough []string, upstreamPort string) (string, *x509.CertPool, func() []transform.PipelineResult) {
	t.Helper()
	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)

	p, getResults := buildSNIProxy(t, []string{"localhost", "allowed.example"}, true)
	p.tlsMode = "mitm"
	p.certCache = cache
	p.passthroughHosts = newPassthroughMatcher(passthrough)
	p.sniUpstreamPort = upstreamPort

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return startTunnelListener(t, p), pool, getResults
}

func TestPassthroughHosts_ListedHostIsNotMITMd(t *testing.T) {
	upstream, upstreamPool := startEchoTLSServer(t)
	_, port, err := net.SplitHostPort(upstream)
	require.NoError(t, err)

	tunnelAddr, _, getResults := buildMITMPassthroughProxy(t, []string{"localhost"}, port)

	// Trust ONLY the upstream's own cert: succeeds only if TLS is not opened.
	tlsConn := connectAndHandshake(t, tunnelAddr, "localhost:"+port, "localhost", upstreamPool)
	_, err = tlsConn.Write([]byte("GET /pt HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "echo /pt\n", string(body))

	// The passthrough audit entry is emitted when the relay ends.
	require.NoError(t, tlsConn.Close())

	require.Eventually(t, func() bool { return len(getResults()) == 2 }, 2*time.Second, 10*time.Millisecond)
	for _, r := range getResults() {
		require.Equal(t, transform.ModeSNIOnly, r.Mode)
		require.Equal(t, transform.ActionContinue, r.Action)
	}
}

func TestPassthroughHosts_UnlistedHostStaysMITM(t *testing.T) {
	upstream, upstreamPool := startEchoTLSServer(t)
	_, port, err := net.SplitHostPort(upstream)
	require.NoError(t, err)

	tunnelAddr, caPool, getResults := buildMITMPassthroughProxy(t, []string{"localhost"}, port)

	// Handshake succeeds against the proxy CA ...
	_ = connectAndHandshake(t, tunnelAddr, "allowed.example:443", "allowed.example", caPool)
	// ... and the CONNECT audit entry is regular mitm mode.
	require.Eventually(t, func() bool { return len(getResults()) >= 1 }, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, transform.ModeMITM, getResults()[0].Mode)

	// The upstream's own cert is not what the client saw.
	conn, err := net.Dial("tcp", tunnelAddr)
	require.NoError(t, err)
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Error(t, tls.Client(conn, &tls.Config{ServerName: "allowed.example", RootCAs: upstreamPool}).Handshake())
}

func TestPassthroughHosts_SNIMustAlsoBeListed(t *testing.T) {
	// Decoy upstream that must never be dialed.
	var dialed atomic.Int32
	decoy := startAcceptLoop(t, func(c net.Conn) {
		dialed.Add(1)
		_ = c.Close()
	})
	_, decoyPort, err := net.SplitHostPort(decoy)
	require.NoError(t, err)

	tunnelAddr, _, getResults := buildMITMPassthroughProxy(t, []string{"localhost"}, decoyPort)

	// CONNECT to the listed host, but the ClientHello names an unlisted
	// host that the allowlist admits.
	conn, err := net.Dial("tcp", tunnelAddr)
	require.NoError(t, err)
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.Error(t, tls.Client(conn, &tls.Config{ServerName: "allowed.example", InsecureSkipVerify: true}).Handshake()) //nolint:gosec // test: only the proxy's reaction to the SNI matters

	require.Eventually(t, func() bool { return len(getResults()) == 2 }, 2*time.Second, 10*time.Millisecond)
	rejected := getResults()[1]
	require.Equal(t, "allowed.example", rejected.SNI)
	require.Equal(t, transform.ActionReject, rejected.Action)
	require.Equal(t, http.StatusForbidden, rejected.StatusCode)
	require.ErrorContains(t, rejected.Err, "tls.passthrough_hosts")
	require.Zero(t, dialed.Load())
}

func TestIsPassthroughHost(t *testing.T) {
	tests := []struct {
		name  string
		hosts []string
		host  string
		want  bool
	}{
		{"no list", nil, "a.example.com", false},
		{"exact", []string{"a.example.com"}, "a.example.com", true},
		{"other host", []string{"a.example.com"}, "b.example.com", false},
		{"glob", []string{"*.example.com"}, "x.example.com", true},
		{"glob matches apex too", []string{"*.example.com"}, "example.com", true},
		{"glob other domain", []string{"*.example.com"}, "example.org", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{passthroughHosts: newPassthroughMatcher(tc.hosts)}
			require.Equal(t, tc.want, p.isPassthroughHost(tc.host))
		})
	}
}
