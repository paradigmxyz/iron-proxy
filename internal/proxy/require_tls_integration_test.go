package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
	_ "github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// End-to-end check for the require_tls rule option, with the secrets
// transform as the credential injector (the case in ironsh/iron-proxy#278).
// The rule option itself is unit-tested in internal/hostmatch; this test
// proves the proxy sets req.TLS the way the option relies on: present for a
// MITM'd HTTPS request, absent for plain HTTP through the tunnel.

const (
	requireTLSHost        = "api.example.com"
	requireTLSPlaceholder = "placeholder-token"
	requireTLSRealSecret  = "real-secret-value"
	requireTLSEnvVar      = "IRON_TEST_REQUIRE_TLS_SECRET"
)

// echoAuthHandler answers with the Authorization header it received, so the
// test can see exactly what went upstream.
var echoAuthHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_, _ = fmt.Fprint(w, r.Header.Get("Authorization"))
})

// startRequireTLSProxy starts a tunnel proxy whose pipeline is
// allowlist -> secrets, with the secret rule's require_tls set as given.
// HTTPS upstream dials go to tlsAddr and plain-HTTP dials go to plainAddr.
func startRequireTLSProxy(t *testing.T, requireTLS bool, tlsAddr, plainAddr string) (tunnelAddr string, caPool *x509.CertPool) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	t.Setenv(requireTLSEnvVar, requireTLSRealSecret)

	al, err := allowlist.New([]string{requireTLSHost}, nil)
	require.NoError(t, err)

	secretsYAML := fmt.Sprintf(`
secrets:
  - source: {type: env, var: %s}
    replace:
      proxy_value: %s
      match_headers: [Authorization]
    rules:
      - host: %s
        require_tls: %t
`, requireTLSEnvVar, requireTLSPlaceholder, requireTLSHost, requireTLS)
	var doc yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(secretsYAML), &doc))
	factory, err := transform.Lookup("secrets")
	require.NoError(t, err)
	secretsTransform, err := factory(*doc.Content[0], logger)
	require.NoError(t, err)

	pipeline := transform.NewPipeline([]transform.Transformer{al, secretsTransform}, transform.BodyLimits{}, logger)
	ca := newIntegrationCA(t)
	p := New(Options{
		HTTPAddr:   "127.0.0.1:0",
		HTTPSAddr:  "127.0.0.1:0",
		TunnelAddr: "127.0.0.1:0",
		CertCache:  ca.certCache,
		Pipeline:   transform.NewPipelineHolder(pipeline),
		Logger:     logger,
	})
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			target := plainAddr
			if strings.HasSuffix(addr, ":443") {
				target = tlsAddr
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, target)
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p.tunnelListener = ln
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleTunnel(conn)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		close(p.tunnelDone)
	})
	return ln.Addr().String(), ca.caPool
}

// sendViaCONNECT opens a CONNECT tunnel to host:port, optionally starts TLS
// inside it, sends one GET with the placeholder token, and returns what the
// upstream says it received.
func sendViaCONNECT(t *testing.T, tunnelAddr string, caPool *x509.CertPool, port int, useTLS bool) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", requireTLSHost, port, requireTLSHost, port)
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var rw io.ReadWriter = struct {
		io.Reader
		io.Writer
	}{br, conn}
	if useTLS {
		tlsConn := tls.Client(conn, &tls.Config{RootCAs: caPool, ServerName: requireTLSHost})
		require.NoError(t, tlsConn.Handshake())
		rw = tlsConn
		br = bufio.NewReader(tlsConn)
	}

	_, err = fmt.Fprintf(rw, "GET /v1 HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n\r\n", requireTLSHost, requireTLSPlaceholder)
	require.NoError(t, err)
	resp, err = http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

// sendAbsoluteFormHTTP sends an absolute-form http:// request straight to
// the tunnel listener (no CONNECT), as an HTTP_PROXY client does.
func sendAbsoluteFormHTTP(t *testing.T, tunnelAddr string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "GET http://%s/v1 HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n\r\n", requireTLSHost, requireTLSHost, requireTLSPlaceholder)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

// With require_tls on, only the HTTPS request gets the real secret. With it
// off (the control rows), plain HTTP gets it too: that is the #278
// behaviour, and it shows this test can tell the difference.
func TestIntegration_RequireTLS_SecretsInjectOnlyInsideTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	tlsUpstream := httptest.NewTLSServer(echoAuthHandler)
	defer tlsUpstream.Close()
	plainUpstream := httptest.NewServer(echoAuthHandler)
	defer plainUpstream.Close()
	tlsAddr := tlsUpstream.Listener.Addr().String()
	plainAddr := plainUpstream.Listener.Addr().String()

	type proxyUnderTest struct {
		tunnelAddr string
		caPool     *x509.CertPool
	}
	proxies := map[bool]proxyUnderTest{}
	for _, requireTLS := range []bool{true, false} {
		tunnelAddr, caPool := startRequireTLSProxy(t, requireTLS, tlsAddr, plainAddr)
		proxies[requireTLS] = proxyUnderTest{tunnelAddr: tunnelAddr, caPool: caPool}
	}

	const (
		httpsViaCONNECT = "https via CONNECT"
		httpViaCONNECT  = "plain http via CONNECT"
		absoluteForm    = "absolute-form http"
	)
	cases := []struct {
		name       string
		requireTLS bool
		send       string
		want       string
	}{
		{name: "require_tls: https via CONNECT gets the real secret", requireTLS: true, send: httpsViaCONNECT, want: requireTLSRealSecret},
		{name: "require_tls: plain http via CONNECT keeps the placeholder", requireTLS: true, send: httpViaCONNECT, want: requireTLSPlaceholder},
		{name: "require_tls: absolute-form http keeps the placeholder", requireTLS: true, send: absoluteForm, want: requireTLSPlaceholder},
		{name: "control, off: https via CONNECT gets the real secret", requireTLS: false, send: httpsViaCONNECT, want: requireTLSRealSecret},
		{name: "control, off: absolute-form http gets the real secret", requireTLS: false, send: absoluteForm, want: requireTLSRealSecret},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			px := proxies[tc.requireTLS]
			var got string
			switch tc.send {
			case httpsViaCONNECT:
				got = sendViaCONNECT(t, px.tunnelAddr, px.caPool, 443, true)
			case httpViaCONNECT:
				got = sendViaCONNECT(t, px.tunnelAddr, px.caPool, 80, false)
			case absoluteForm:
				got = sendAbsoluteFormHTTP(t, px.tunnelAddr)
			default:
				t.Fatalf("unknown send mode %q", tc.send)
			}
			require.Equal(t, "Bearer "+tc.want, got)
		})
	}
}
