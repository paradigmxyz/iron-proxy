package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// issueCert returns a certificate for name signed by the CA, for a server or a client.
func issueCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, name string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600))
}

type reverseFixture struct {
	proxy     *Proxy
	addr      string
	serverCAs *x509.CertPool
	client    tls.Certificate
	stranger  tls.Certificate
}

// startReverseProxy starts a proxy whose reverse listener serves "proxy.test"
// and trusts one client CA. Upstream TLS certificates are not verified, so
// tests can use httptest upstreams.
func startReverseProxy(t *testing.T, transforms []transform.Transformer) reverseFixture {
	t.Helper()
	dir := t.TempDir()

	serverCA, serverCAKey := generateTestCA(t)
	server := issueCert(t, serverCA, serverCAKey, "proxy.test", x509.ExtKeyUsageServerAuth)
	writePEM(t, filepath.Join(dir, "server.crt"), "CERTIFICATE", server.Certificate[0])
	serverKey, err := x509.MarshalECPrivateKey(server.PrivateKey.(*ecdsa.PrivateKey))
	require.NoError(t, err)
	writePEM(t, filepath.Join(dir, "server.key"), "EC PRIVATE KEY", serverKey)

	clientCA, clientCAKey := generateTestCA(t)
	writePEM(t, filepath.Join(dir, "clients.crt"), "CERTIFICATE", clientCA.Raw)
	strangerCA, strangerCAKey := generateTestCA(t)

	reverseTLS, err := ReverseTLSConfig(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "clients.crt"))
	require.NoError(t, err)

	mitmCA, mitmKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(mitmCA, mitmKey, 100, 72*time.Hour)
	require.NoError(t, err)
	p := New(Options{
		HTTPAddr:    "127.0.0.1:0",
		HTTPSAddr:   "127.0.0.1:0",
		ReverseAddr: "127.0.0.1:0",
		ReverseTLS:  reverseTLS,
		CertCache:   cache,
		Pipeline:    transform.NewPipelineHolder(transform.NewPipeline(transforms, transform.BodyLimits{}, testLogger())),
		Logger:      testLogger(),
	})
	p.transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.reverseServer.Serve(tls.NewListener(ln, p.reverseServer.TLSConfig)) }()
	t.Cleanup(func() { _ = p.reverseServer.Close() })

	serverCAs := x509.NewCertPool()
	serverCAs.AddCert(serverCA)
	return reverseFixture{
		proxy:     p,
		addr:      ln.Addr().String(),
		serverCAs: serverCAs,
		client:    issueCert(t, clientCA, clientCAKey, "worker", x509.ExtKeyUsageClientAuth),
		stranger:  issueCert(t, strangerCA, strangerCAKey, "stranger", x509.ExtKeyUsageClientAuth),
	}
}

func (f reverseFixture) tlsConfig(certs ...tls.Certificate) *tls.Config {
	return &tls.Config{RootCAs: f.serverCAs, ServerName: "proxy.test", Certificates: certs}
}

func (f reverseFixture) httpClient(certs ...tls.Certificate) *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: f.tlsConfig(certs...),
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, f.addr)
		},
	}}
}

func TestReverse_ForwardsToNamedUpstream(t *testing.T) {
	type seen struct {
		host, path, query string
		header            http.Header
	}
	got := make(chan seen, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{r.Host, r.URL.Path, r.URL.RawQuery, r.Header.Clone()}
		_, _ = fmt.Fprint(w, "hello from upstream")
	}))
	defer upstream.Close()
	upstreamHost := upstream.Listener.Addr().String()

	injector := &replacerTransform{reqHeaders: http.Header{"Authorization": {"Bearer real"}}}
	f := startReverseProxy(t, []transform.Transformer{injector})

	req, err := http.NewRequest("POST", fmt.Sprintf("https://proxy.test/%s/v1/things?x=1", upstreamHost), nil)
	require.NoError(t, err)
	req.Header.Set("Cf-Worker", "example.com")
	req.Header.Set("Cf-Connecting-Ip", "203.0.113.1")
	req.Header.Set("Cdn-Loop", "cloudflare")
	req.Header.Set("X-Keep", "yes")
	resp, err := f.httpClient(f.client).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "hello from upstream", string(body))
	upstreamSaw := <-got
	require.Equal(t, upstreamHost, upstreamSaw.host)
	require.Equal(t, "/v1/things", upstreamSaw.path)
	require.Equal(t, "x=1", upstreamSaw.query)
	require.Equal(t, "Bearer real", upstreamSaw.header.Get("Authorization"))
	require.Equal(t, "yes", upstreamSaw.header.Get("X-Keep"))
	require.Empty(t, upstreamSaw.header.Get("Cf-Worker"))
	require.Empty(t, upstreamSaw.header.Get("Cf-Connecting-Ip"))
	require.Empty(t, upstreamSaw.header.Get("Cdn-Loop"))
}

func TestReverse_RequiresClientCertificate(t *testing.T) {
	f := startReverseProxy(t, nil)
	cases := []struct {
		name  string
		certs []tls.Certificate
	}{
		{name: "no certificate"},
		{name: "certificate from another CA", certs: []tls.Certificate{f.stranger}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := f.httpClient(tc.certs...).Get("https://proxy.test/example.com/")
			if resp != nil {
				_ = resp.Body.Close()
			}
			require.Error(t, err)
		})
	}
}

func TestReverse_RejectsPathsWithoutUpstream(t *testing.T) {
	f := startReverseProxy(t, nil)
	cases := []struct {
		name string
		path string
	}{
		{name: "no host", path: "/"},
		{name: "empty host", path: "//example.com/x"},
		{name: "encoded host", path: "/%65xample.com/x"},
		{name: "userinfo", path: "/user@example.com/x"},
		{name: "port out of range", path: "/example.com:99999/x"},
		{name: "dot segments after the host", path: "/example.com/a/%2E%2E/b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "https://proxy.test/", nil)
			require.NoError(t, err)
			req.URL.Opaque = tc.path
			resp, err := f.httpClient(f.client).Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestReverse_TransformsCanReject(t *testing.T) {
	f := startReverseProxy(t, []transform.Transformer{&rejectTransform{}})
	resp, err := f.httpClient(f.client).Get("https://proxy.test/example.com/")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestReverse_WebSocketToTLSUpstream(t *testing.T) {
	upstreamCA, upstreamCAKey := generateTestCA(t)
	upstreamCert := issueCert(t, upstreamCA, upstreamCAKey, "127.0.0.1", x509.ExtKeyUsageServerAuth)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{upstreamCert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	paths := make(chan string, 1)
	protocols := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		protocols <- tlsConn.ConnectionState().NegotiatedProtocol
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		paths <- req.URL.Path
		if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			return
		}
		_, _ = io.Copy(conn, br) // Echo until the client closes.
	}()

	f := startReverseProxy(t, nil)
	// The upstream transport offers h2 once it has served a request; the
	// WebSocket dial must still negotiate HTTP/1.1.
	f.proxy.transport.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
	conn, err := tls.Dial("tcp", f.addr, f.tlsConfig(f.client))
	require.NoError(t, err)
	defer conn.Close()
	br := bufio.NewReader(conn)
	_, err = fmt.Fprintf(conn, "GET /%s/v1/responses HTTP/1.1\r\n"+
		"Host: proxy.test\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n", ln.Addr().String())
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	require.Equal(t, "http/1.1", <-protocols)
	require.Equal(t, "/v1/responses", <-paths)

	_, err = conn.Write([]byte("hello websocket"))
	require.NoError(t, err)
	buf := make([]byte, 64)
	n, err := br.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello websocket", string(buf[:n]))
}
