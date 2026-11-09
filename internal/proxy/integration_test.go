package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	"golang.org/x/net/http2"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/responseretry"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
)

func newResponseRetryTestProxy(
	t *testing.T,
	authorizer *httptest.Server,
	status int,
	transforms []transform.Transformer,
	maxRequestBodyBytes int64,
) *Proxy {
	t.Helper()
	handler, err := responseretry.New(responseretry.Options{
		AuthorizeEndpoint: authorizer.URL + "/authorize",
		CompleteEndpoint:  authorizer.URL + "/complete",
		Token:             "proxy-token",
		SandboxID:         "sandbox-1",
		Statuses:          []int{status},
		CompletionHeaders: []string{"Payment-Receipt"},
		Client:            authorizer.Client(),
	})
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pipeline := transform.NewPipeline(transforms, transform.BodyLimits{
		MaxRequestBodyBytes:  maxRequestBodyBytes,
		MaxResponseBodyBytes: 1 << 20,
	}, logger)
	return New(Options{
		Pipeline:             transform.NewPipelineHolder(pipeline),
		Logger:               logger,
		ResponseRetryHandler: handler,
	})
}

func TestIntegration_ResponseHandlerReplaysExactTransformedRequestOnce(t *testing.T) {
	const originalBody = "original request body"
	const transformedBody = "transformed request body"
	const chargeTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		gotBody, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, transformedBody, string(gotBody))
		require.Equal(t, "transformed", r.Header.Get("X-Transformed"))
		if r.Header.Get("X-Retry-Token") == "retry-token" {
			require.Equal(t, chargeTraceparent, r.Header.Get("Traceparent"))
			_, err := w.Write([]byte("paid"))
			require.NoError(t, err)
			return
		}
		w.Header().Set("X-Retry-Challenge", "challenge")
		w.WriteHeader(http.StatusConflict)
	}))
	defer upstream.Close()

	completions := 0
	authorizer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer proxy-token", r.Header.Get("Authorization"))
		if r.URL.Path == "/complete" {
			completions++
			var payload responseretry.CompletionRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			require.Equal(t, chargeTraceparent, payload.Traceparent)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, err := fmt.Fprintf(w, `{"retry":true,"attempt_id":"8ace71a1-4e12-47e5-9df4-f2f660db6a82","traceparent":%q,"headers":{"X-Retry-Token":"retry-token"}}`, chargeTraceparent)
		require.NoError(t, err)
	}))
	defer authorizer.Close()
	p := newResponseRetryTestProxy(
		t,
		authorizer,
		http.StatusConflict,
		[]transform.Transformer{&replacerTransform{
			reqBody:    []byte(transformedBody),
			reqHeaders: http.Header{"X-Transformed": {"transformed"}},
		}},
		1<<20,
	)
	req := httptest.NewRequest(http.MethodPost, upstream.URL+"/paid", strings.NewReader(originalBody))
	recorder := httptest.NewRecorder()

	p.handleDirectHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "paid", recorder.Body.String())
	require.Equal(t, 2, calls)
	require.Equal(t, 1, completions)
}

func TestIntegration_ResponseHandlerReturnsOriginalChallengeForOversizedRequest(t *testing.T) {
	const body = "request is larger than the replay limit"
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		gotBody, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, body, string(gotBody))
		w.Header().Set("Www-Authenticate", "Payment challenge")
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte("original challenge"))
	}))
	defer upstream.Close()

	authorizeCalls := 0
	authorizer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizeCalls++
		var payload responseretry.DecisionRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.Equal(t, "http", payload.Scheme)
		require.False(t, payload.Replayable)
		_, _ = w.Write([]byte(`{"retry":false,"headers":{}}`))
	}))
	defer authorizer.Close()
	p := newResponseRetryTestProxy(t, authorizer, http.StatusPaymentRequired, nil, 8)
	req := httptest.NewRequest(http.MethodPost, upstream.URL+"/paid", strings.NewReader(body))
	recorder := httptest.NewRecorder()

	p.handleDirectHTTP(recorder, req)

	require.Equal(t, http.StatusPaymentRequired, recorder.Code)
	require.Equal(t, "original challenge", recorder.Body.String())
	require.Equal(t, 1, upstreamCalls)
	require.Equal(t, 1, authorizeCalls)
}

func TestIntegration_ResponseHandlerBypassesStreamingRequests(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		unknownSize bool
	}{
		{name: "gRPC", contentType: "application/grpc+proto"},
		{name: "unknown length", contentType: "application/octet-stream", unknownSize: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const body = "streamed request body"
			upstreamCalls := 0
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls++
				gotBody, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.Equal(t, body, string(gotBody))
				w.WriteHeader(http.StatusPaymentRequired)
				_, err = io.WriteString(w, "original challenge")
				require.NoError(t, err)
			}))
			defer upstream.Close()

			authorizeCalls := 0
			authorizer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				authorizeCalls++
				http.Error(w, "unexpected", http.StatusInternalServerError)
			}))
			defer authorizer.Close()
			p := newResponseRetryTestProxy(t, authorizer, http.StatusPaymentRequired, nil, 1<<20)
			var requestBody io.Reader = strings.NewReader(body)
			if tc.unknownSize {
				requestBody = struct{ io.Reader }{Reader: requestBody}
			}
			req := httptest.NewRequest(http.MethodPost, upstream.URL+"/paid", requestBody)
			req.Header.Set("Content-Type", tc.contentType)
			if tc.unknownSize {
				require.Equal(t, int64(-1), req.ContentLength)
			}
			recorder := httptest.NewRecorder()

			p.handleDirectHTTP(recorder, req)

			require.Equal(t, http.StatusPaymentRequired, recorder.Code)
			require.Equal(t, "original challenge", recorder.Body.String())
			require.Equal(t, 1, upstreamCalls)
			require.Zero(t, authorizeCalls)
		})
	}
}

func TestIntegration_ResponseHandlerFailureReturnsOriginalChallenge(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte("original challenge"))
	}))
	defer upstream.Close()
	authorizer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer authorizer.Close()
	p := newResponseRetryTestProxy(t, authorizer, http.StatusPaymentRequired, nil, 1<<20)
	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/paid", nil)
	recorder := httptest.NewRecorder()

	p.handleDirectHTTP(recorder, req)

	require.Equal(t, http.StatusPaymentRequired, recorder.Code)
	require.Equal(t, "original challenge", recorder.Body.String())
}

func TestIntegration_ResponseHandlerNeverRetriesAReplay(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusPaymentRequired)
		_, err := fmt.Fprintf(w, "challenge %d", upstreamCalls)
		require.NoError(t, err)
	}))
	defer upstream.Close()

	authorizeCalls := 0
	completionCalls := 0
	authorizer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			authorizeCalls++
			_, err := io.WriteString(w, `{"retry":true,"attempt_id":"8ace71a1-4e12-47e5-9df4-f2f660db6a82","headers":{"X-Retry-Token":"retry-token"}}`)
			require.NoError(t, err)
		case "/complete":
			completionCalls++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer authorizer.Close()
	p := newResponseRetryTestProxy(t, authorizer, http.StatusPaymentRequired, nil, 1<<20)
	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/paid", nil)
	recorder := httptest.NewRecorder()

	p.handleDirectHTTP(recorder, req)

	require.Equal(t, http.StatusPaymentRequired, recorder.Code)
	require.Equal(t, "challenge 2", recorder.Body.String())
	require.Equal(t, 2, upstreamCalls)
	require.Equal(t, 1, authorizeCalls)
	require.Equal(t, 1, completionCalls)
}

func TestIntegration_ResponseHandlerReportsReplayTransportFailure(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		if upstreamCalls == 1 {
			w.WriteHeader(http.StatusPaymentRequired)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	}))
	defer upstream.Close()

	completionCalls := 0
	authorizer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/complete" {
			completionCalls++
			var payload responseretry.CompletionRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			require.Nil(t, payload.ReplayStatus)
			require.Equal(t, "upstream_transport_error", payload.TransportError)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, err := io.WriteString(w, `{"retry":true,"attempt_id":"8ace71a1-4e12-47e5-9df4-f2f660db6a82","headers":{"X-Retry-Token":"retry-token"}}`)
		require.NoError(t, err)
	}))
	defer authorizer.Close()
	p := newResponseRetryTestProxy(t, authorizer, http.StatusPaymentRequired, nil, 1<<20)
	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/paid", nil)
	recorder := httptest.NewRecorder()

	p.handleDirectHTTP(recorder, req)

	require.Equal(t, http.StatusBadGateway, recorder.Code)
	require.Equal(t, 2, upstreamCalls)
	require.Equal(t, 1, completionCalls)
}

func TestIntegration_ResponseHandlerCompletionFailureDoesNotHideReplay(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		if upstreamCalls == 1 {
			w.WriteHeader(http.StatusPaymentRequired)
			return
		}
		_, err := io.WriteString(w, "paid")
		require.NoError(t, err)
	}))
	defer upstream.Close()

	completionCalls := 0
	authorizer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/complete" {
			completionCalls++
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, err := io.WriteString(w, `{"retry":true,"attempt_id":"8ace71a1-4e12-47e5-9df4-f2f660db6a82","headers":{"X-Retry-Token":"retry-token"}}`)
		require.NoError(t, err)
	}))
	defer authorizer.Close()
	p := newResponseRetryTestProxy(t, authorizer, http.StatusPaymentRequired, nil, 1<<20)
	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/paid", nil)
	recorder := httptest.NewRecorder()

	p.handleDirectHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "paid", recorder.Body.String())
	require.Equal(t, 2, upstreamCalls)
	require.Equal(t, 2, completionCalls)
}

// integrationCA bundles the test CA certificate, cert cache, and trust pool.
type integrationCA struct {
	certCache *certcache.Cache
	caPool    *x509.CertPool
}

// newIntegrationCA generates a test CA and returns the cert cache and CA pool.
func newIntegrationCA(t *testing.T) integrationCA {
	t.Helper()

	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return integrationCA{certCache: cache, caPool: pool}
}

// startTunnelIntegrationProxy creates a proxy with an allowlist and tunnel
// listener, returning the proxy, tunnel address, and CA pool.
func startTunnelIntegrationProxy(t *testing.T, allowedHosts []string, logger *slog.Logger) (*Proxy, string, *x509.CertPool) {
	t.Helper()

	ca := newIntegrationCA(t)

	al, err := allowlist.New(allowedHosts, nil)
	require.NoError(t, err)
	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)
	holder := transform.NewPipelineHolder(pipeline)

	p := New(Options{
		HTTPAddr:   "127.0.0.1:0",
		HTTPSAddr:  "127.0.0.1:0",
		TunnelAddr: "127.0.0.1:0",
		CertCache:  ca.certCache,
		Pipeline:   holder,
		Logger:     logger,
	})

	tunnelLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tunnelAddr := tunnelLn.Addr().String()
	p.tunnelListener = tunnelLn

	go func() {
		for {
			conn, err := tunnelLn.Accept()
			if err != nil {
				return
			}
			go p.handleTunnel(conn)
		}
	}()
	t.Cleanup(func() {
		tunnelLn.Close()
		close(p.tunnelDone)
	})

	return p, tunnelAddr, ca.caPool
}

// TestIntegration_DNSToProxyToUpstream is an end-to-end test that exercises:
// DNS interception -> TLS MITM -> allowlist transform -> upstream -> response.
func TestIntegration_DNSToProxyToUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// 1. Start an upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "integration test response")
	}))
	defer upstream.Close()

	upstreamAddr := upstream.Listener.Addr().String()

	// We use a fake hostname for SNI since the proxy needs a domain, not an IP.
	const fakeHost = "test-upstream.example.com"

	// 2. Generate CA and cert cache
	ca := newIntegrationCA(t)

	// 3. Build transform pipeline with allowlist
	al, err := allowlist.New([]string{fakeHost}, nil)
	require.NoError(t, err)

	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)
	holder := transform.NewPipelineHolder(pipeline)

	// 4. Start proxy with HTTPS
	p := New(Options{
		HTTPAddr:  "127.0.0.1:0",
		HTTPSAddr: "127.0.0.1:0",
		CertCache: ca.certCache,
		Pipeline:  holder,
		Logger:    logger,
	})

	// Start HTTP listener
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	httpAddr := httpLn.Addr().String()

	// Start HTTPS listener
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

	// 6. Override upstream transport to route fakeHost to the real upstream
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		// Redirect all dials to the actual upstream address
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	// 7. Test: allowed request through HTTPS proxy
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    ca.caPool,
				ServerName: fakeHost,
			},
		},
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", httpsAddr), nil)
	require.NoError(t, err)
	req.Host = fakeHost

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "true", resp.Header.Get("X-Upstream"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "integration test response", string(body))

	// 8. Test: denied request (host not in allowlist)
	req2, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", httpAddr), nil)
	require.NoError(t, err)
	req2.Host = "evil.example.com"

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	require.Equal(t, http.StatusForbidden, resp2.StatusCode)
}

// TestIntegration_CONNECT exercises the full CONNECT tunnel flow:
// client CONNECT -> tunnel handshake -> TLS MITM -> allowlist -> upstream -> response.
func TestIntegration_CONNECT(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 1. Start upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "connect integration response")
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()

	const allowedHost = "allowed.example.com"
	const deniedHost = "denied.example.com"

	p, tunnelAddr, caPool := startTunnelIntegrationProxy(t, []string{allowedHost}, logger)

	// Override transport to route all dials to the real upstream
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	// 2. Test: allowed CONNECT -> TLS MITM -> success
	t.Run("allowed", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		// Send CONNECT
		_, err = fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", allowedHost, allowedHost)
		require.NoError(t, err)

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// TLS handshake over the tunnel
		tlsConn := tls.Client(conn, &tls.Config{
			RootCAs:    caPool,
			ServerName: allowedHost,
		})
		defer func() { _ = tlsConn.Close() }()
		require.NoError(t, tlsConn.Handshake())

		// HTTP request over the TLS tunnel
		req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", allowedHost), nil)
		require.NoError(t, err)
		require.NoError(t, req.Write(tlsConn))

		resp2, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
		require.NoError(t, err)
		defer resp2.Body.Close()

		require.Equal(t, http.StatusOK, resp2.StatusCode)
		require.Equal(t, "true", resp2.Header.Get("X-Upstream"))
		body, err := io.ReadAll(resp2.Body)
		require.NoError(t, err)
		require.Equal(t, "connect integration response", string(body))
	})

	// 3. Test: denied CONNECT -> 403
	t.Run("denied", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		_, err = fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", deniedHost, deniedHost)
		require.NoError(t, err)

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	// 4. Test: allowed CONNECT -> plain HTTP (non-TLS)
	t.Run("allowed_plain_http", func(t *testing.T) {
		// Start a plain HTTP upstream
		plainUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "plain http response")
		}))
		defer plainUpstream.Close()
		plainAddr := plainUpstream.Listener.Addr().String()

		// Override transport for this sub-test to route to the plain upstream
		origTransport := p.transport
		p.transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, plainAddr)
			},
		}
		defer func() { p.transport = origTransport }()

		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		_, err = fmt.Fprintf(conn, "CONNECT %s:80 HTTP/1.1\r\nHost: %s:80\r\n\r\n", allowedHost, allowedHost)
		require.NoError(t, err)

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Send plain HTTP through the tunnel
		_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", allowedHost)
		require.NoError(t, err)

		resp2, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		defer resp2.Body.Close()

		require.Equal(t, http.StatusOK, resp2.StatusCode)
		body, err := io.ReadAll(resp2.Body)
		require.NoError(t, err)
		require.Equal(t, "plain http response", string(body))
	})
}

// TestIntegration_SOCKS5 exercises the full SOCKS5 tunnel flow:
// client SOCKS5 -> tunnel handshake -> TLS MITM -> allowlist -> upstream -> response.
func TestIntegration_SOCKS5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 1. Start upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "socks5 integration response")
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()

	const allowedHost = "allowed.example.com"
	const deniedHost = "denied.example.com"

	p, tunnelAddr, caPool := startTunnelIntegrationProxy(t, []string{allowedHost}, logger)

	// Override transport to route all dials to the real upstream
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	// Helper: perform SOCKS5 handshake with domain-name address type
	socks5Connect := func(t *testing.T, conn net.Conn, host string, port uint16) {
		t.Helper()

		// Auth: offer no-auth
		_, err := conn.Write([]byte{0x05, 0x01, 0x00})
		require.NoError(t, err)

		authResp := make([]byte, 2)
		_, err = io.ReadFull(conn, authResp)
		require.NoError(t, err)
		require.Equal(t, []byte{0x05, 0x00}, authResp)

		// Connect request with domain name
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
		portBuf := make([]byte, 2)
		portBuf[0] = byte(port >> 8)
		portBuf[1] = byte(port)
		req = append(req, portBuf...)
		_, err = conn.Write(req)
		require.NoError(t, err)
	}

	readSocks5Reply := func(t *testing.T, conn net.Conn) byte {
		t.Helper()
		reply := make([]byte, 10) // IPv4 reply is always 10 bytes
		_, err := io.ReadFull(conn, reply)
		require.NoError(t, err)
		require.Equal(t, byte(0x05), reply[0])
		return reply[1] // status
	}

	// 2. Test: allowed SOCKS5 -> TLS MITM -> success
	t.Run("allowed_tls", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		socks5Connect(t, conn, allowedHost, 443)
		status := readSocks5Reply(t, conn)
		require.Equal(t, byte(0x00), status, "expected SOCKS5 success")

		// TLS handshake
		tlsConn := tls.Client(conn, &tls.Config{
			RootCAs:    caPool,
			ServerName: allowedHost,
		})
		defer func() { _ = tlsConn.Close() }()
		require.NoError(t, tlsConn.Handshake())

		// HTTP request
		req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", allowedHost), nil)
		require.NoError(t, err)
		require.NoError(t, req.Write(tlsConn))

		resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "true", resp.Header.Get("X-Upstream"))
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, "socks5 integration response", string(body))
	})

	// 3. Test: denied SOCKS5 -> connection not allowed
	t.Run("denied", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		socks5Connect(t, conn, deniedHost, 443)
		status := readSocks5Reply(t, conn)
		require.Equal(t, byte(0x02), status, "expected SOCKS5 connection not allowed")
	})

	// 4. Test: allowed SOCKS5 -> plain HTTP
	t.Run("allowed_plain_http", func(t *testing.T) {
		plainUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "socks5 plain http")
		}))
		defer plainUpstream.Close()
		plainAddr := plainUpstream.Listener.Addr().String()

		origTransport := p.transport
		p.transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, plainAddr)
			},
		}
		defer func() { p.transport = origTransport }()

		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		socks5Connect(t, conn, allowedHost, 80)
		status := readSocks5Reply(t, conn)
		require.Equal(t, byte(0x00), status, "expected SOCKS5 success")

		// Send plain HTTP
		_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", allowedHost)
		require.NoError(t, err)

		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, "socks5 plain http", string(body))
	})

	// 5. Test: non-HTTP/TLS protocol -> proxy closes the connection
	t.Run("unsupported_protocol", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		socks5Connect(t, conn, allowedHost, 22)
		status := readSocks5Reply(t, conn)
		require.Equal(t, byte(0x00), status, "SOCKS5 handshake should succeed")

		// Send something that is neither TLS (0x16) nor an HTTP method (A-Z).
		// SSH banner starts with "SSH-", but let's send raw binary to be explicit.
		_, err = conn.Write([]byte{0x00, 0x01, 0x02, 0x03})
		require.NoError(t, err)

		// The proxy should close the connection without forwarding anything.
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		require.ErrorIs(t, err, io.EOF, "expected proxy to close the connection")
	})
}

// TestIntegration_CONNECT_HTTP2 verifies a gRPC-style HTTP/2 client can tunnel
// through the MITM proxy: ALPN negotiates h2 on both the client->proxy and
// proxy->upstream hops, and upstream trailers (where gRPC carries grpc-status)
// reach the client. This is the regression test for HTTP/2/gRPC MITM support.
func TestIntegration_CONNECT_HTTP2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// HTTP/2 upstream that records its negotiated protocol and sends a trailer
	// after the body, mirroring how gRPC delivers grpc-status.
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Test-Trailer")
		w.Header().Set("X-Upstream-Proto", r.Proto)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "h2 integration response")
		w.Header().Set("X-Test-Trailer", "trailer-value")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()

	const allowedHost = "allowed.example.com"
	p, tunnelAddr, caPool := startTunnelIntegrationProxy(t, []string{allowedHost}, logger)

	// Route all dials to the h2 upstream. ForceAttemptHTTP2 mirrors the
	// production buildTransport change so the proxy negotiates h2 upstream.
	p.transport = &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	// HTTP/2 client that CONNECT-tunnels through the proxy and trusts the MITM CA.
	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				ServerName: allowedHost,
				NextProtos: []string{"h2"},
			},
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
				if err != nil {
					return nil, err
				}
				if _, err := fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", allowedHost, allowedHost); err != nil {
					_ = conn.Close()
					return nil, err
				}
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					_ = conn.Close()
					return nil, err
				}
				if resp.StatusCode != http.StatusOK {
					_ = conn.Close()
					return nil, fmt.Errorf("CONNECT failed: %d", resp.StatusCode)
				}
				tlsConn := tls.Client(conn, cfg)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					_ = conn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
	}
	defer client.CloseIdleConnections()

	resp, err := client.Get(fmt.Sprintf("https://%s/test", allowedHost))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, 2, resp.ProtoMajor, "client<->proxy hop must be HTTP/2")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "h2 integration response", string(body))
	require.Equal(t, "HTTP/2.0", resp.Header.Get("X-Upstream-Proto"), "proxy<->upstream hop must be HTTP/2")
	// The trailer must survive proxying — this is where gRPC carries grpc-status.
	require.Equal(t, "trailer-value", resp.Trailer.Get("X-Test-Trailer"))
}

// startDirectHTTPSProxy starts a proxy serving its direct HTTPS (MITM) listener
// (not the CONNECT tunnel) and routes all upstream dials to upstreamAddr.
// Returns the proxy, the HTTPS listener address, and the CA pool to trust.
func startDirectHTTPSProxy(t *testing.T, allowedHosts []string, upstreamAddr string, logger *slog.Logger) (*Proxy, string, *x509.CertPool) {
	t.Helper()

	ca := newIntegrationCA(t)
	al, err := allowlist.New(allowedHosts, nil)
	require.NoError(t, err)
	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)
	holder := transform.NewPipelineHolder(pipeline)

	p := New(Options{
		HTTPAddr:  "127.0.0.1:0",
		HTTPSAddr: "127.0.0.1:0",
		CertCache: ca.certCache,
		Pipeline:  holder,
		Logger:    logger,
	})

	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tlsLn := tls.NewListener(httpsLn, p.httpsServer.TLSConfig)
	httpsAddr := httpsLn.Addr().String()
	go func() { _ = p.httpsServer.Serve(tlsLn) }()
	t.Cleanup(func() { _ = p.httpsServer.Close() })

	p.transport = &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}
	return p, httpsAddr, ca.caPool
}

// trailerUpstream returns an HTTP/2 test server that sends a body followed by a
// trailer, mirroring how gRPC delivers grpc-status.
func trailerUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Test-Trailer")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "trailer body")
		w.Header().Set("X-Test-Trailer", "trailer-value")
	}))
	s.EnableHTTP2 = true
	s.StartTLS()
	return s
}

// TestIntegration_DirectHTTPS_HTTP2 verifies the direct HTTPS MITM listener
// (not the CONNECT tunnel) negotiates h2 and forwards response trailers.
func TestIntegration_DirectHTTPS_HTTP2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	upstream := trailerUpstream(t)
	defer upstream.Close()

	const fakeHost = "direct-h2.example.com"
	_, httpsAddr, caPool := startDirectHTTPSProxy(t, []string{fakeHost}, upstream.Listener.Addr().String(), logger)

	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: fakeHost, NextProtos: []string{"h2"}},
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", httpsAddr)
			},
		},
	}
	defer client.CloseIdleConnections()

	resp, err := client.Get("https://" + fakeHost + "/test")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, 2, resp.ProtoMajor, "direct HTTPS listener must serve HTTP/2")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "trailer body", string(body))
	require.Equal(t, "trailer-value", resp.Trailer.Get("X-Test-Trailer"))
}

// bodyReadingTransform reads the request body, like any match_body transform.
type bodyReadingTransform struct {
	replacement []byte
}

func (bodyReadingTransform) Name() string { return "body_reader" }

func (b bodyReadingTransform) TransformRequest(_ context.Context, _ *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if _, err := io.ReadAll(req.Body); err != nil {
		return nil, err
	}
	if b.replacement != nil {
		transform.RequireBufferedBody(req.Body).ReplaceBuffered(b.replacement)
	}
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (bodyReadingTransform) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func TestIntegration_RequestBodyBeyondLimitIsForwarded(t *testing.T) {
	const limit = 8
	const body = "0123456789abcdef"

	cases := []struct {
		name          string
		replacement   []byte
		contentLength int64
		wantBody      string
		wantLength    int64
	}{
		{name: "content length", contentLength: int64(len(body)), wantBody: body, wantLength: int64(len(body))},
		{name: "chunked", contentLength: -1, wantBody: body, wantLength: -1},
		{
			name:          "replaced prefix with content length",
			replacement:   []byte("ABCDEFGHIJ"),
			contentLength: int64(len(body)),
			wantBody:      "ABCDEFGHIJ89abcdef",
			wantLength:    18,
		},
		{
			name:          "replaced prefix chunked",
			replacement:   []byte("ABCDEFGHIJ"),
			contentLength: -1,
			wantBody:      "ABCDEFGHIJ89abcdef",
			wantLength:    -1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotBody string
			var gotLength int64
			upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				data, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				gotBody = string(data)
				gotLength = r.ContentLength
			}))
			defer upstream.Close()

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			pipeline := transform.NewPipeline(
				[]transform.Transformer{bodyReadingTransform{replacement: tc.replacement}},
				transform.BodyLimits{MaxRequestBodyBytes: limit},
				logger,
			)
			p := New(Options{Pipeline: transform.NewPipelineHolder(pipeline), Logger: logger})

			req := httptest.NewRequest(http.MethodPost, upstream.URL+"/upload", strings.NewReader(body))
			req.ContentLength = tc.contentLength
			recorder := httptest.NewRecorder()

			p.handleDirectHTTP(recorder, req)

			require.Equal(t, http.StatusOK, recorder.Code)
			require.Equal(t, tc.wantBody, gotBody)
			require.Equal(t, tc.wantLength, gotLength)
		})
	}
}
