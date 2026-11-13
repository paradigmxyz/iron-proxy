package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/mcp"
	"github.com/ironsh/iron-proxy/internal/mcpgateway"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

func startProxy(t *testing.T) (*Proxy, string, string, *x509.CertPool) {
	t.Helper()
	return startProxyWithTransforms(t, nil)
}

// replacerTransform replaces request and response bodies with fixed-size padding.
type replacerTransform struct {
	reqBody    []byte
	reqHeaders http.Header
	respBody   []byte
}

func (r *replacerTransform) Name() string { return "replacer" }

func (r *replacerTransform) TransformRequest(_ context.Context, _ *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if r.reqBody != nil {
		// Read the original body to trigger buffering, then replace it.
		if _, err := io.ReadAll(req.Body); err != nil {
			return nil, err
		}
		req.Body = transform.NewBufferedBodyFromBytes(r.reqBody)
		req.ContentLength = int64(len(r.reqBody))
	}
	copyHeaders(req.Header, r.reqHeaders)
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (r *replacerTransform) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, resp *http.Response) (*transform.TransformResult, error) {
	if r.respBody != nil {
		if _, err := io.ReadAll(resp.Body); err != nil {
			return nil, err
		}
		resp.Body = transform.NewBufferedBodyFromBytes(r.respBody)
		resp.ContentLength = int64(len(r.respBody))
	}
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func startProxyWithTransforms(t *testing.T, transforms []transform.Transformer) (*Proxy, string, string, *x509.CertPool) {
	t.Helper()

	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)

	pipeline := transform.NewPipeline(transforms, transform.BodyLimits{}, testLogger())
	holder := transform.NewPipelineHolder(pipeline)
	p := New(Options{
		HTTPAddr:  "127.0.0.1:0",
		HTTPSAddr: "127.0.0.1:0",
		CertCache: cache,
		Pipeline:  holder,
		Logger:    testLogger(),
	})

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	httpAddr := httpLn.Addr().String()

	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tlsLn := tls.NewListener(httpsLn, p.httpsServer.TLSConfig)
	httpsAddr := httpsLn.Addr().String()

	go func() { _ = p.httpServer.Serve(httpLn) }()
	go func() { _ = p.httpsServer.Serve(tlsLn) }()

	t.Cleanup(func() {
		_ = p.httpServer.Close()
		_ = p.httpsServer.Close()
	})

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return p, httpAddr, httpsAddr, pool
}

func startHTTPProxyWithMCP(t *testing.T, policy *mcp.Policy, gateway *mcpgateway.Gateway) (*Proxy, string) {
	t.Helper()
	pipeline := transform.NewPipeline(nil, transform.BodyLimits{}, testLogger())
	p := New(Options{
		HTTPAddr:   "127.0.0.1:0",
		Pipeline:   transform.NewPipelineHolder(pipeline),
		MCPPolicy:  mcp.NewPolicyHolder(policy),
		MCPGateway: mcpgateway.NewHolder(gateway),
		Logger:     testLogger(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.httpServer.Serve(ln) }()
	t.Cleanup(func() { _ = p.httpServer.Close() })
	return p, ln.Addr().String()
}

func mustYAMLNode(t *testing.T, src string) yaml.Node {
	t.Helper()
	var doc yaml.Node
	err := yaml.Unmarshal([]byte(src), &doc)
	require.NoError(t, err)
	require.Equal(t, yaml.DocumentNode, doc.Kind)
	require.NotEmpty(t, doc.Content)
	return *doc.Content[0]
}

func TestHTTPProxy(t *testing.T) {
	// Start an upstream HTTP server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "upstream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from upstream")
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	// Send request through the proxy, targeting the upstream
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", httpAddr), nil)
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "upstream", resp.Header.Get("X-Test"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from upstream", string(body))
}

func TestHTTPProxy_PostBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "echo: %s", body)
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/echo", httpAddr),
		strings.NewReader("request body"))
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "echo: request body", string(body))
}

func TestMCPGatewayRoutesAllowedCallWithCredential(t *testing.T) {
	t.Setenv("MCP_TOKEN", "real-token")

	reached := make(chan struct{}, 1)
	var wantHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- struct{}{}
		require.Equal(t, "Bearer real-token", r.Header.Get("Authorization"))
		require.Equal(t, "/upstream", r.URL.Path)
		require.Equal(t, wantHost, r.Host)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), `"tools/call"`)
		w.Header().Set("Content-Type", "application/json")
		_, err = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
		require.NoError(t, err)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	wantHost = upstreamURL.Host

	policy, err := mcp.Compile(mcp.Config{
		Servers: []mcp.ServerConfig{{
			Name:  "github",
			Rules: []hostmatch.RuleConfig{{Host: "github.mcp.local", Paths: []string{"/mcp"}}},
			Tools: []mcp.ToolConfig{{Name: "search_repositories"}},
		}},
	})
	require.NoError(t, err)
	gateway, err := mcpgateway.Compile(mcpgateway.Config{
		Routes: []mcpgateway.RouteConfig{{
			Name:     "github",
			Rules:    []hostmatch.RuleConfig{{Host: "github.mcp.local", Paths: []string{"/mcp"}}},
			Upstream: upstreamURL.String() + "/upstream",
			Credentials: []mcpgateway.CredentialConfig{{
				Source: mustYAMLNode(t, `type: env
var: MCP_TOKEN
`),
				Inject: mcpgateway.InjectConfig{
					Header:    "Authorization",
					Formatter: "Bearer {{ .Value }}",
				},
			}},
		}},
	})
	require.NoError(t, err)
	_, proxyAddr := startHTTPProxyWithMCP(t, policy, gateway)

	req, err := http.NewRequest(http.MethodPost, "http://"+proxyAddr+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_repositories","arguments":{}}}`))
	require.NoError(t, err)
	req.Host = "github.mcp.local"
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("gateway upstream was not reached")
	}
}

func TestMCPGatewayDeniedToolDoesNotReachUpstream(t *testing.T) {
	var reached atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	policy, err := mcp.Compile(mcp.Config{
		Servers: []mcp.ServerConfig{{
			Name:  "github",
			Rules: []hostmatch.RuleConfig{{Host: "github.mcp.local", Paths: []string{"/mcp"}}},
			Tools: []mcp.ToolConfig{{Name: "search_repositories"}},
		}},
	})
	require.NoError(t, err)
	gateway, err := mcpgateway.Compile(mcpgateway.Config{
		Routes: []mcpgateway.RouteConfig{{
			Name:     "github",
			Rules:    []hostmatch.RuleConfig{{Host: "github.mcp.local", Paths: []string{"/mcp"}}},
			Upstream: upstreamURL.String(),
		}},
	})
	require.NoError(t, err)
	_, proxyAddr := startHTTPProxyWithMCP(t, policy, gateway)

	req, err := http.NewRequest(http.MethodPost, "http://"+proxyAddr+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repository","arguments":{}}}`))
	require.NoError(t, err)
	req.Host = "github.mcp.local"
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(body), "blocked by iron-proxy policy")
	require.Equal(t, int32(0), reached.Load())
}

func TestHTTPSProxy(t *testing.T) {
	// Start an upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from tls upstream")
	}))
	defer upstream.Close()

	p, _, httpsAddr, caPool := startProxy(t)

	// We need to route the request to the proxy but with the upstream's Host.
	// The proxy will make a TLS connection to the upstream.
	// For this test, we need the proxy's upstream transport to trust the
	// upstream's self-signed cert. Override it temporarily.
	// Use a fake hostname so Go's TLS actually sends SNI (it won't for IPs).
	const fakeHost = "test.example.com"
	upstreamAddr := upstream.Listener.Addr().String()

	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		// Route fakeHost to the actual upstream
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				ServerName: fakeHost,
			},
			// Route the fake hostname to the proxy's actual address
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, httpsAddr)
			},
		},
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", fakeHost), nil)
	require.NoError(t, err)
	// Host defaults to fakeHost — matches SNI

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from tls upstream", string(body))
}

func TestHTTPSProxy_SNIHostMismatch(t *testing.T) {
	_, _, httpsAddr, caPool := startProxy(t)

	// SNI says "sni.example.com" but Host says "other.example.com"
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				ServerName: "sni.example.com",
			},
		},
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", httpsAddr), nil)
	require.NoError(t, err)
	req.Host = "other.example.com"

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHTTPProxy_ClientCancel(t *testing.T) {
	// Upstream that blocks on a release channel so the client has a window to
	// cancel its context while the proxy is mid-RoundTrip.
	release := make(chan struct{})
	reached := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(reached)
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	defer close(release)

	pipeline := transform.NewPipeline(nil, transform.BodyLimits{}, testLogger())

	var mu sync.Mutex
	var results []transform.PipelineResult
	done := make(chan struct{})
	pipeline.SetAuditFunc(func(r *transform.PipelineResult) {
		mu.Lock()
		results = append(results, *r)
		mu.Unlock()
		close(done)
	})

	p := New(Options{
		HTTPAddr: "127.0.0.1:0",
		Pipeline: transform.NewPipelineHolder(pipeline),
		Logger:   testLogger(),
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.httpServer.Serve(ln) }()
	t.Cleanup(func() { _ = p.httpServer.Close() })
	proxyAddr := ln.Addr().String()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, "GET", upstream.URL+"/slow", nil)
	require.NoError(t, err)

	reqErr := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		reqErr <- err
	}()

	// Wait for the proxy to reach upstream, then cancel.
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never reached")
	}
	cancel()

	select {
	case err := <-reqErr:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("client Do never returned")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("audit never fired")
	}

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, results, 1)
	r := results[0]
	require.True(t, r.ClientCanceled)
	require.Equal(t, http.StatusOK, r.StatusCode)
	require.NoError(t, r.Err)
	require.Equal(t, transform.ActionContinue, r.Action)
}

func TestHTTPProxy_UpstreamError(t *testing.T) {
	_, httpAddr, _, _ := startProxy(t)

	// Request to a host that won't connect
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", httpAddr), nil)
	require.NoError(t, err)
	req.Host = "127.0.0.1:1" // nothing listening

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

func TestHTTPProxy_HeadersCopied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back a request header as a response header
		w.Header().Set("X-Echo", r.Header.Get("X-Custom"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", httpAddr), nil)
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()
	req.Header.Set("X-Custom", "test-value")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "test-value", resp.Header.Get("X-Echo"))
}

func TestHTTPProxy_WebSocketUpgrade(t *testing.T) {
	// Start a raw TCP server that speaks the WebSocket upgrade handshake
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer upstreamLn.Close()

	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the upgrade request
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		_ = n

		// Send upgrade response
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n\r\n"
		_, _ = conn.Write([]byte(resp))

		// Echo loop: read and write back
		for {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			_, _ = conn.Write(buf[:n])
		}
	}()

	_, httpAddr, _, _ := startProxy(t)

	// Dial the proxy as a raw TCP client
	conn, err := net.DialTimeout("tcp", httpAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Send WebSocket upgrade request through the proxy
	upgradeReq := fmt.Sprintf("GET /ws HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n",
		upstreamLn.Addr().String())
	_, err = conn.Write([]byte(upgradeReq))
	require.NoError(t, err)

	// Read the 101 response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	response := string(buf[:n])
	require.Contains(t, response, "101")
	require.Contains(t, response, "Upgrade")

	// Send data and expect echo
	_, err = conn.Write([]byte("hello websocket"))
	require.NoError(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = conn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello websocket", string(buf[:n]))
}

func TestHTTPProxy_SSEStreaming(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}

		events := []string{
			"data: event1\n\n",
			"data: event2\n\n",
			"data: event3\n\n",
		}
		for _, event := range events {
			_, _ = fmt.Fprint(w, event)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/events", httpAddr), nil)
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "data: event1")
	require.Contains(t, string(body), "data: event2")
	require.Contains(t, string(body), "data: event3")
}

func TestHTTPProxy_RequestContentLengthPreserved(t *testing.T) {
	const requestBody = "fixed-size request body"
	var gotContentLength int64
	var gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentLength = r.ContentLength
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/test", httpAddr),
		strings.NewReader(requestBody))
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(len(requestBody)), gotContentLength)
	require.Equal(t, requestBody, gotBody)
}

func TestHTTPProxy_GetHeadBodyless(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			var gotBody []byte
			var hasContentLengthHeader bool
			var hasTransferEncoding bool

			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, hasContentLengthHeader = r.Header["Content-Length"]
				hasTransferEncoding = len(r.TransferEncoding) > 0
				if r.Body != nil {
					gotBody, _ = io.ReadAll(r.Body)
				}
				w.WriteHeader(http.StatusOK)
				if r.Method != http.MethodHead {
					_, _ = fmt.Fprint(w, "response body")
				}
			}))
			defer upstream.Close()

			_, httpAddr, _, _ := startProxy(t)

			req, err := http.NewRequest(method, fmt.Sprintf("http://%s/test", httpAddr), nil)
			require.NoError(t, err)
			req.Host = upstream.Listener.Addr().String()

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Empty(t, gotBody)
			require.False(t, hasContentLengthHeader, "body-less %s request should not send Content-Length header upstream", method)
			require.False(t, hasTransferEncoding, "body-less %s request should not send Transfer-Encoding header upstream", method)
		})
	}
}

func TestHTTPProxy_ContentLengthPreserved(t *testing.T) {
	const responseBody = "fixed-size body"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(responseBody)))
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, responseBody)
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", httpAddr), nil)
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(len(responseBody)), resp.ContentLength)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, responseBody, string(body))
}

func TestHTTPProxy_TransformReplacesRequestBody(t *testing.T) {
	replacedBody := strings.Repeat("X", 42)
	var gotContentLength int64
	var gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentLength = r.ContentLength
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxyWithTransforms(t, []transform.Transformer{
		&replacerTransform{reqBody: []byte(replacedBody)},
	})

	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/test", httpAddr),
		strings.NewReader("original body"))
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(len(replacedBody)), gotContentLength)
	require.Equal(t, replacedBody, gotBody)
}

func TestHTTPProxy_TransformReplacesResponseBody(t *testing.T) {
	replacedBody := strings.Repeat("Y", 37)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "original response")
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxyWithTransforms(t, []transform.Transformer{
		&replacerTransform{respBody: []byte(replacedBody)},
	})

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", httpAddr), nil)
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(len(replacedBody)), resp.ContentLength)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, replacedBody, string(body))
}

func TestHTTPProxy_HopByHopHeadersStripped(t *testing.T) {
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	// Dial the proxy as a raw TCP client so we can send arbitrary hop-by-hop
	// headers without Go's client library normalizing them away.
	conn, err := net.DialTimeout("tcp", httpAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	rawReq := fmt.Sprintf("GET /test HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Proxy-Authorization: Basic c2VjcmV0\r\n"+
		"Proxy-Connection: keep-alive\r\n"+
		"Connection: Cookie\r\n"+
		"Cookie: session=leaky\r\n"+
		"X-Custom: keepme\r\n"+
		"\r\n",
		upstream.Listener.Addr().String())
	_, err = conn.Write([]byte(rawReq))
	require.NoError(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	_, err = conn.Read(buf)
	require.NoError(t, err)

	require.NotNil(t, gotHeaders)
	require.Empty(t, gotHeaders.Get("Proxy-Authorization"))
	require.Empty(t, gotHeaders.Get("Proxy-Connection"))
	require.Empty(t, gotHeaders.Get("Cookie"), "Cookie was named by Connection and must not be forwarded")
	require.Equal(t, "keepme", gotHeaders.Get("X-Custom"))
}

func TestHTTPProxy_WebSocketHopByHopHeadersStripped(t *testing.T) {
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer upstreamLn.Close()

	gotReqCh := make(chan []byte, 1)
	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		gotReqCh <- append([]byte(nil), buf[:n]...)
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n\r\n"
		_, _ = conn.Write([]byte(resp))
		_, _ = io.Copy(io.Discard, conn)
	}()

	_, httpAddr, _, _ := startProxy(t)

	conn, err := net.DialTimeout("tcp", httpAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	upgradeReq := fmt.Sprintf("GET /ws HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade, Cookie\r\n"+
		"Cookie: session=leaky\r\n"+
		"Proxy-Authorization: Basic c2VjcmV0\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n",
		upstreamLn.Addr().String())
	_, err = conn.Write([]byte(upgradeReq))
	require.NoError(t, err)

	var rawUpstream []byte
	select {
	case rawUpstream = <-gotReqCh:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not receive request")
	}

	upstreamStr := string(rawUpstream)
	require.NotContains(t, upstreamStr, "Proxy-Authorization")
	require.NotContains(t, upstreamStr, "session=leaky")
	require.NotContains(t, strings.ToLower(upstreamStr), "cookie:")
	// Go canonicalizes "Sec-WebSocket-Key" to "Sec-Websocket-Key" when the
	// header is parsed through the server and re-serialized.
	lower := strings.ToLower(upstreamStr)
	require.Contains(t, lower, "sec-websocket-key")
	require.Contains(t, lower, "upgrade: websocket")
	require.Contains(t, lower, "connection: upgrade")
}

func TestIsWebSocketUpgrade(t *testing.T) {
	cases := []struct {
		name       string
		upgrade    string
		connection string
		want       bool
	}{
		{"valid upgrade", "websocket", "Upgrade", true},
		{"upgrade with extra tokens", "websocket", "keep-alive, Upgrade", true},
		{"case insensitive", "WebSocket", "upgrade", true},
		{"missing upgrade header", "", "Upgrade", false},
		{"connection substring not token", "websocket", "notupgrade", false},
		{"connection no upgrade", "websocket", "keep-alive", false},
		{"upgrade not websocket", "h2c", "Upgrade", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}}
			if tc.upgrade != "" {
				r.Header.Set("Upgrade", tc.upgrade)
			}
			if tc.connection != "" {
				r.Header.Set("Connection", tc.connection)
			}
			require.Equal(t, tc.want, isWebSocketUpgrade(r))
		})
	}
}

func TestHTTPProxy_RejectsDotSegmentPaths(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	// Use a raw TCP write so the dot-segment path is not normalized by the
	// Go client before reaching the proxy.
	conn, err := net.DialTimeout("tcp", httpAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	rawReq := fmt.Sprintf("GET /public/../admin/secret HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"\r\n",
		upstream.Listener.Addr().String())
	_, err = conn.Write([]byte(rawReq))
	require.NoError(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	require.NoError(t, err)

	require.Contains(t, string(buf[:n]), "400")
	require.False(t, upstreamHit, "upstream must not be reached for dot-segment paths")
}

// TestHTTPProxy_PreservesEscapedSlashes verifies that %2F in the request
// path is forwarded to the upstream as %2F rather than being decoded to /.
// Some APIs (e.g. GCS object names under /o/<object>) treat encoded vs
// decoded slashes as distinct path segments. See issue #155.
func TestHTTPProxy_PreservesEscapedSlashes(t *testing.T) {
	var gotRequestURI string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI = r.RequestURI
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	// Send via raw TCP to keep the Go client from normalizing %2F.
	conn, err := net.DialTimeout("tcp", httpAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	const rawPath = "/download/storage/v1/b/bkt/o/dir%2Fsub%2Ffile.gz?alt=media"
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		rawPath, upstream.Listener.Addr().String())
	_, err = conn.Write([]byte(rawReq))
	require.NoError(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	_, err = conn.Read(buf)
	require.NoError(t, err)

	require.Equal(t, rawPath, gotRequestURI)
}

func TestContainsDotSegments(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/admin/secret", false},
		{"/admin/.secret", false},
		{"/admin/..secret", false},
		{"/", false},
		{"/public/../admin", true},
		{"/./admin", true},
		{"/admin/..", true},
		{"/admin/.", true},
		{"..", true},
		{".", true},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			require.Equal(t, tc.want, containsDotSegments(tc.path))
		})
	}
}

func TestPrepareReplayBodyBoundaries(t *testing.T) {
	cases := []struct {
		name          string
		body          string
		contentLength int64
		limit         int64
		wantReplay    bool
	}{
		{name: "below limit", body: "1234", contentLength: 4, limit: 5, wantReplay: true},
		{name: "at limit", body: "12345", contentLength: 5, limit: 5, wantReplay: true},
		{name: "known over limit", body: "123456", contentLength: 6, limit: 5, wantReplay: false},
		{name: "unknown at limit", body: "12345", contentLength: -1, limit: 5, wantReplay: true},
		{name: "unknown over limit", body: "123456", contentLength: -1, limit: 5, wantReplay: false},
		{name: "disabled", body: "12345", contentLength: 5, limit: 0, wantReplay: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prepared, replayBody, replayable, err := prepareReplayBody(
				io.NopCloser(strings.NewReader(tc.body)),
				tc.contentLength,
				tc.limit,
			)
			require.NoError(t, err)
			require.Equal(t, tc.wantReplay, replayable)
			if tc.wantReplay {
				require.Equal(t, []byte(tc.body), replayBody)
			} else {
				require.Nil(t, replayBody)
			}
			got, err := io.ReadAll(prepared)
			require.NoError(t, err)
			require.NoError(t, prepared.Close())
			require.Equal(t, tc.body, string(got))
		})
	}
}

func TestResponseRetryEligible(t *testing.T) {
	cases := []struct {
		name          string
		method        string
		contentType   string
		contentLength int64
		connection    string
		upgrade       string
		want          bool
	}{
		{name: "ordinary GET", method: http.MethodGet, contentLength: 0, want: true},
		{name: "ordinary HEAD", method: http.MethodHead, contentLength: 0, want: true},
		{name: "ordinary known body", method: http.MethodPost, contentType: "application/json", contentLength: 4, want: true},
		{name: "known body with content type parameters", method: http.MethodPost, contentType: "application/json; charset=utf-8", contentLength: 4, want: true},
		{name: "known body without content type", method: http.MethodPost, contentLength: 4, want: true},
		{name: "unknown length with content type", method: http.MethodPost, contentType: "application/json", contentLength: -1, want: false},
		{name: "unknown length without content type", method: http.MethodPost, contentLength: -1, want: false},
		{name: "gRPC", method: http.MethodPost, contentType: "application/grpc", contentLength: 4, want: false},
		{name: "gRPC proto", method: http.MethodPost, contentType: "application/grpc+proto", contentLength: 4, want: false},
		{name: "gRPC JSON", method: http.MethodPost, contentType: "application/grpc+json", contentLength: 4, want: false},
		{name: "gRPC web", method: http.MethodPost, contentType: "application/grpc-web", contentLength: 4, want: false},
		{name: "gRPC web text", method: http.MethodPost, contentType: "application/grpc-web-text", contentLength: 4, want: false},
		{name: "gRPC web mixed case and parameters", method: http.MethodPost, contentType: " Application/GRPC-Web+Proto ; charset=utf-8", contentLength: 4, want: false},
		{name: "gRPC prefix is conservative", method: http.MethodPost, contentType: "application/grpcish", contentLength: 4, want: false},
		{name: "WebSocket", method: http.MethodGet, contentLength: 0, connection: "Upgrade", upgrade: "websocket", want: false},
		{name: "WebSocket mixed case and connection tokens", method: http.MethodGet, contentLength: 0, connection: "keep-alive, UpGrAdE", upgrade: "WebSocket", want: false},
		{name: "upgrade without connection header", method: http.MethodGet, contentLength: 0, upgrade: "websocket", want: true},
		{name: "connection upgrade without protocol", method: http.MethodGet, contentLength: 0, connection: "Upgrade", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader
			if tc.contentLength != 0 {
				body = strings.NewReader("body")
			}
			req := httptest.NewRequest(tc.method, "https://service.example/", body)
			req.ContentLength = tc.contentLength
			req.Header.Set("Content-Type", tc.contentType)
			req.Header.Set("Connection", tc.connection)
			req.Header.Set("Upgrade", tc.upgrade)

			require.Equal(t, tc.want, responseRetryEligible(req))
		})
	}
}

func TestHTTPProxy_FailsClosedUntilReady(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)

	pipeline := transform.NewPipeline(nil, transform.BodyLimits{}, testLogger())
	audits := make(chan transform.PipelineResult, 2)
	pipeline.SetAuditFunc(func(r *transform.PipelineResult) {
		audits <- *r
	})
	holder := transform.NewPipelineHolder(pipeline)

	var ready atomic.Bool
	p := New(Options{
		HTTPAddr:  "127.0.0.1:0",
		CertCache: cache,
		Pipeline:  holder,
		Logger:    testLogger(),
		Ready:     ready.Load,
	})

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.httpServer.Serve(httpLn) }()
	t.Cleanup(func() { _ = p.httpServer.Close() })

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", httpLn.Addr()), nil)
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	// Not ready: the proxy must reject rather than pass the request through
	// an un-synced pipeline.
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	audit := <-audits
	require.Equal(t, transform.ActionReject, audit.Action)
	require.Equal(t, http.StatusServiceUnavailable, audit.StatusCode)
	require.Len(t, audit.RequestTransforms, 1)
	require.Equal(t, "ready", audit.RequestTransforms[0].Name)
	require.Equal(t, transform.ActionReject, audit.RequestTransforms[0].Action)

	// Ready: the same request flows.
	ready.Store(true)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
