package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
)

const unixTestHost = "llm-gateway.internal"

// shortSocketPath returns a socket path in a fresh temp dir. t.TempDir can
// exceed the 104-byte sun_path limit on macOS, so use a short prefix.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ipuds")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "up.sock")
}

// startUnixHTTPUpstream serves handler over plain HTTP on a Unix socket and
// returns the socket path.
func startUnixHTTPUpstream(t *testing.T, handler http.Handler) string {
	t.Helper()
	path := shortSocketPath(t)
	ln, err := net.Listen("unix", path)
	require.NoError(t, err)
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return path
}

type unixSocketTestProxy struct {
	p         *Proxy
	httpAddr  string
	httpsAddr string
	pool      *x509.CertPool
	tcpDials  *atomic.Int32
	audits    func() []transform.PipelineResult
}

// startUnixSocketProxy starts a MITM proxy with an allowlist for allowed and
// unixTestHost mapped to socketPath. The default upstream deny list is
// active, and the TCP transport only counts dials so a test can assert that
// no TCP fallback happens.
func startUnixSocketProxy(t *testing.T, allowed []string, socketPath string) unixSocketTestProxy {
	t.Helper()
	logger := testLogger()

	al, err := allowlist.New(allowed, nil)
	require.NoError(t, err)
	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)
	var mu sync.Mutex
	var results []transform.PipelineResult
	pipeline.SetAuditFunc(func(r *transform.PipelineResult) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, *r)
	})

	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)
	guard, err := dnsguard.New(dnsguard.DefaultDenyCIDRs)
	require.NoError(t, err)

	p := New(Options{
		HTTPAddr:            "127.0.0.1:0",
		HTTPSAddr:           "127.0.0.1:0",
		CertCache:           cache,
		Pipeline:            transform.NewPipelineHolder(pipeline),
		Guard:               guard,
		Logger:              logger,
		UpstreamUnixSockets: []config.UpstreamUnixSocket{{Host: unixTestHost, Path: socketPath}},
	})

	var tcpDials atomic.Int32
	p.transport = &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			tcpDials.Add(1)
			return nil, fmt.Errorf("unexpected tcp dial")
		},
	}

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.httpServer.Serve(httpLn) }()
	go func() { _ = p.httpsServer.Serve(tls.NewListener(httpsLn, p.httpsServer.TLSConfig)) }()
	t.Cleanup(func() {
		_ = p.httpServer.Close()
		_ = p.httpsServer.Close()
	})

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return unixSocketTestProxy{
		p:         p,
		httpAddr:  httpLn.Addr().String(),
		httpsAddr: httpsLn.Addr().String(),
		pool:      pool,
		tcpDials:  &tcpDials,
		audits: func() []transform.PipelineResult {
			mu.Lock()
			defer mu.Unlock()
			return append([]transform.PipelineResult(nil), results...)
		},
	}
}

// do sends a request for unixTestHost through the proxy's HTTP or HTTPS
// (MITM) listener.
func (tp unixSocketTestProxy) do(t *testing.T, scheme, host, path string) *http.Response {
	t.Helper()
	addr := tp.httpAddr
	if scheme == "https" {
		addr = tp.httpsAddr
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: tp.pool, ServerName: unixTestHost},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
			},
		},
	}
	req, err := http.NewRequest("GET", scheme+"://"+unixTestHost+path, nil)
	require.NoError(t, err)
	req.Host = host
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestUnixSocketUpstream_ForwardsPlainHTTP(t *testing.T) {
	type seen struct {
		host string
		tls  bool
		path string
	}
	seenCh := make(chan seen, 1)
	socketPath := startUnixHTTPUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCh <- seen{host: r.Host, tls: r.TLS != nil, path: r.URL.Path}
		_, _ = fmt.Fprint(w, "from unix socket")
	}))

	cases := []struct {
		name     string
		scheme   string
		host     string
		wantHost string
	}{
		{name: "http", scheme: "http", host: unixTestHost, wantHost: unixTestHost},
		{name: "https mitm", scheme: "https", host: unixTestHost, wantHost: unixTestHost},
		{name: "host with port", scheme: "http", host: unixTestHost + ":8080", wantHost: unixTestHost + ":8080"},
		{name: "mixed case", scheme: "http", host: "LLM-Gateway.Internal", wantHost: "LLM-Gateway.Internal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tp := startUnixSocketProxy(t, []string{unixTestHost}, socketPath)

			resp := tp.do(t, tc.scheme, tc.host, "/v1/models")
			require.Equal(t, http.StatusOK, resp.StatusCode)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, "from unix socket", string(body))

			got := <-seenCh
			require.Equal(t, tc.wantHost, got.host)
			require.False(t, got.tls, "upstream must receive plain HTTP")
			require.Equal(t, "/v1/models", got.path)
			require.Zero(t, tp.tcpDials.Load())

			require.Eventually(t, func() bool { return len(tp.audits()) == 1 }, 2*time.Second, 10*time.Millisecond)
			audit := tp.audits()[0]
			require.Equal(t, transform.ActionContinue, audit.Action)
			require.Equal(t, http.StatusOK, audit.StatusCode)
		})
	}
}

func TestUnixSocketUpstream_AllowlistStillApplies(t *testing.T) {
	var hits atomic.Int32
	socketPath := startUnixHTTPUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	tp := startUnixSocketProxy(t, []string{"other.example"}, socketPath)

	resp := tp.do(t, "http", unixTestHost, "/")
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.Zero(t, hits.Load())
	require.Zero(t, tp.tcpDials.Load())

	require.Eventually(t, func() bool { return len(tp.audits()) == 1 }, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, transform.ActionReject, tp.audits()[0].Action)
}

func TestUnixSocketUpstream_MissingSocketFailsClosed(t *testing.T) {
	tp := startUnixSocketProxy(t, []string{unixTestHost}, shortSocketPath(t))

	for _, scheme := range []string{"http", "https"} {
		resp := tp.do(t, scheme, unixTestHost, "/")
		require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	}
	require.Zero(t, tp.tcpDials.Load(), "must not fall back to TCP")

	require.Eventually(t, func() bool { return len(tp.audits()) == 2 }, 2*time.Second, 10*time.Millisecond)
	for _, audit := range tp.audits() {
		require.Equal(t, http.StatusBadGateway, audit.StatusCode)
		require.ErrorContains(t, audit.Err, "upstream unix socket")
	}
}

func TestUnixSocketUpstream_UnmappedHostUsesTCPPath(t *testing.T) {
	socketPath := startUnixHTTPUpstream(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("unmapped host reached the unix socket")
	}))
	tp := startUnixSocketProxy(t, []string{"*"}, socketPath)

	req, err := http.NewRequest("GET", "http://"+tp.httpAddr+"/", nil)
	require.NoError(t, err)
	req.Host = "gateway.internal"
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	require.Equal(t, int32(1), tp.tcpDials.Load())
}

func TestUnixSocketUpstream_SSEStreams(t *testing.T) {
	release := make(chan struct{})
	socketPath := startUnixHTTPUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "data: event1\n\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = fmt.Fprint(w, "data: event2\n\n")
	}))
	tp := startUnixSocketProxy(t, []string{unixTestHost}, socketPath)

	resp := tp.do(t, "https", unixTestHost, "/v1/chat/completions")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	// event1 must arrive while the upstream still holds the stream open.
	br := bufio.NewReader(resp.Body)
	lineCh := make(chan string, 1)
	go func() {
		line, _ := br.ReadString('\n') // error surfaces as a missing line below
		lineCh <- line
	}()
	select {
	case line := <-lineCh:
		require.Equal(t, "data: event1\n", line)
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("first SSE event was not streamed before the upstream finished")
	}
	close(release)

	rest, err := io.ReadAll(br)
	require.NoError(t, err)
	require.Contains(t, string(rest), "data: event2")
}

func TestUnixSocketUpstream_WebSocket(t *testing.T) {
	socketPath := shortSocketPath(t)
	ln, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	hostCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		hostCh <- req.Host
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_, _ = io.Copy(conn, br) // echo until the client closes
	}()

	tp := startUnixSocketProxy(t, []string{unixTestHost}, socketPath)

	conn, err := net.DialTimeout("tcp", tp.httpAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", unixTestHost)
	require.NoError(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	require.Equal(t, unixTestHost, <-hostCh)

	_, err = io.WriteString(conn, "hello websocket")
	require.NoError(t, err)
	buf := make([]byte, len("hello websocket"))
	_, err = io.ReadFull(br, buf)
	require.NoError(t, err)
	require.Equal(t, "hello websocket", string(buf))
	require.Zero(t, tp.tcpDials.Load())
}

func TestSNIPassthrough_UnixSocketHostFailsClosed(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = upstream.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	_, upstreamPort, err := net.SplitHostPort(upstream.Addr().String())
	require.NoError(t, err)

	p, getResults := buildSNIProxy(t, []string{"localhost"}, false)
	p.sniUpstreamPort = upstreamPort
	p.unixSockets = map[string]string{"localhost": shortSocketPath(t)}
	proxyAddr := startAcceptLoop(t, func(c net.Conn) { _ = p.serveSNIPassthrough(c) })

	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true})
	require.Error(t, tlsConn.Handshake())

	require.Eventually(t, func() bool { return len(getResults()) == 1 }, 2*time.Second, 10*time.Millisecond)
	result := getResults()[0]
	require.Equal(t, http.StatusBadGateway, result.StatusCode)
	require.ErrorContains(t, result.Err, "unix socket")
	require.Zero(t, accepted.Load(), "must not fall back to TCP")
}
