package proxy

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/tenancy"
	"github.com/ironsh/iron-proxy/internal/transform"
	_ "github.com/ironsh/iron-proxy/internal/transform/secrets" // registers the secrets transform
)

const (
	tenancyCPToken  = "proxy-control-plane-token"
	tenancyIssuer   = "test-issuer"
	tenancyAudience = "test-audience"
	tenancyHost     = "api.example.com"
)

// signTenantToken mints an EdDSA JWT for sub, valid until exp.
func signTenantToken(t *testing.T, key ed25519.PrivateKey, sub string, exp time.Time) string {
	t.Helper()
	enc := func(v any) string {
		data, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signed := enc(map[string]string{"alg": "EdDSA", "typ": "JWT"}) + "." + enc(map[string]any{
		"iss": tenancyIssuer,
		"aud": tenancyAudience,
		"sub": sub,
		"jti": "exe_" + sub,
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
	})
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(signed)))
}

// tenantControlPlane serves each subject a config that injects its own API
// key and its tenant token. It records the bearer tokens it was called with.
type tenantControlPlane struct {
	mu      sync.Mutex
	tokens  []string
	status  int
	server  *httptest.Server
	subject func(token string) string
}

func (cp *tenantControlPlane) handle(w http.ResponseWriter, r *http.Request) {
	// The proxy authenticates as itself; the tenant token only selects.
	if r.Header.Get("Authorization") != "Bearer "+tenancyCPToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	token := r.Header.Get(tenancy.TenantTokenHeader)
	cp.mu.Lock()
	cp.tokens = append(cp.tokens, token)
	status := cp.status
	cp.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	sub := cp.subject(token)
	secrets := []map[string]any{
		{
			"source": map[string]any{"type": "control_plane", "value": "key-for-" + sub},
			"inject": map[string]any{"header": "X-Api-Key"},
			"rules":  []map[string]any{{"host": tenancyHost}},
		},
		{
			"source": map[string]any{"type": "tenant_token"},
			"inject": map[string]any{"header": "X-Tenant-Token"},
			"rules":  []map[string]any{{"host": tenancyHost}},
		},
	}
	_ = json.NewEncoder(w).Encode(map[string]any{ // the test client reads what it gets
		"config_hash": "hash-" + sub,
		"secrets":     secrets,
	})
}

func (cp *tenantControlPlane) calls() []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return append([]string(nil), cp.tokens...)
}

// buildTestPipeline mirrors cmd/iron-proxy's tenant pipeline builder, with
// extra transformers run first.
func buildTestPipeline(t *testing.T, extra ...transform.Transformer) tenancy.Builder {
	return func(rules, secretsRaw, transformsRaw json.RawMessage) (*transform.Pipeline, error) {
		transforms, err := config.TransformsFromSync(rules, secretsRaw, transformsRaw)
		if err != nil {
			return nil, err
		}
		transformers := append([]transform.Transformer(nil), extra...)
		for _, tc := range transforms {
			factory, err := transform.Lookup(tc.Name)
			if err != nil {
				return nil, err
			}
			tr, err := factory(tc.Config, testLogger())
			if err != nil {
				return nil, err
			}
			transformers = append(transformers, tr)
		}
		return transform.NewPipeline(transformers, transform.BodyLimits{}, testLogger()), nil
	}
}

type tenancyFixture struct {
	proxy      *Proxy
	tunnelAddr string
	caPool     *x509.CertPool
	key        ed25519.PrivateKey
	cp         *tenantControlPlane
	seen       chan http.Header
	// register tells the fake control plane which subject a token is for.
	register func(token, sub string)
}

func startTenancyProxy(t *testing.T) *tenancyFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cp := &tenantControlPlane{}
	keyOf := map[string]string{}
	var keysMu sync.Mutex
	cp.subject = func(token string) string {
		keysMu.Lock()
		defer keysMu.Unlock()
		return keyOf[token]
	}
	cp.server = httptest.NewServer(http.HandlerFunc(cp.handle))
	t.Cleanup(cp.server.Close)

	seen := make(chan http.Header, 16)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		_, _ = fmt.Fprint(w, "ok") // the client asserts on the headers, not this body
	}))
	t.Cleanup(upstream.Close)

	caCert, caKey := generateTestCA(t)
	certs, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)
	cache := tenancy.New(tenancy.Options{
		Verifier:          tenancy.NewVerifier([]ed25519.PublicKey{public}, tenancyIssuer, tenancyAudience),
		URL:               cp.server.URL,
		ControlPlaneToken: tenancyCPToken,
		FreshFor:          time.Minute,
		StaleFor:          10 * time.Minute,
		Build:             buildTestPipeline(t),
		Logger:            testLogger(),
	})
	p := New(Options{
		TunnelAddr: "127.0.0.1:0",
		CertCache:  certs,
		Pipeline:   transform.NewPipelineHolder(transform.NewPipeline(nil, transform.BodyLimits{}, testLogger())),
		Logger:     testLogger(),
		Tenancy:    cache,
	})
	upstreamAddr := upstream.Listener.Addr().String()
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // the upstream is a local test server
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
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
		_ = ln.Close() // the accept loop exits on close
		close(p.tunnelDone)
	})

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	fx := &tenancyFixture{proxy: p, tunnelAddr: ln.Addr().String(), caPool: pool, key: private, cp: cp, seen: seen}
	fx.register = func(token, sub string) {
		keysMu.Lock()
		defer keysMu.Unlock()
		keyOf[token] = sub
	}
	return fx
}

// token mints a token for sub and registers it with the fake control plane.
func (fx *tenancyFixture) token(t *testing.T, sub string, exp time.Time) string {
	token := signTenantToken(t, fx.key, sub, exp)
	fx.register(token, sub)
	return token
}

// connect sends a CONNECT with the given Proxy-Authorization (none if empty)
// and returns the response and the connection.
func (fx *tenancyFixture) connect(t *testing.T, auth string) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fx.tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	header := ""
	if auth != "" {
		header = "Proxy-Authorization: " + auth + "\r\n"
	}
	_, err = fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n%s\r\n", tenancyHost, tenancyHost, header)
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	return resp, conn, br
}

// get sends one request over a MITM'd tunnel and returns the response.
func (fx *tenancyFixture) get(t *testing.T, tlsConn *tls.Conn, br *bufio.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://"+tenancyHost+"/v1/thing", nil)
	require.NoError(t, err)
	require.NoError(t, req.Write(tlsConn))
	resp, err := http.ReadResponse(br, req)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	return resp
}

func (fx *tenancyFixture) tunnel(t *testing.T, token string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	resp, conn, _ := fx.connect(t, "Bearer "+token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tlsConn := tls.Client(conn, &tls.Config{RootCAs: fx.caPool, ServerName: tenancyHost})
	require.NoError(t, tlsConn.Handshake())
	return tlsConn, bufio.NewReader(tlsConn)
}

func TestTenancy_ConnectRequiresAValidToken(t *testing.T) {
	fx := startTenancyProxy(t)
	cases := []struct {
		name string
		auth string
		code string
	}{
		{"missing", "", "tenant_token_required"},
		{"not bearer", "Basic dXNlcjpwYXNz", "tenant_token_required"},
		{"garbage", "Bearer not-a-jwt", "tenant_token_invalid"},
		{"expired", "Bearer " + fx.token(t, "prn_a", time.Now().Add(-time.Hour)), "tenant_token_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, _, _ := fx.connect(t, tc.auth)
			require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
			require.Equal(t, `Bearer realm="iron-proxy"`, resp.Header.Get("Proxy-Authenticate"))
			require.Equal(t, tc.code, resp.Header.Get(tenancyErrorHeader))
		})
	}
	require.Empty(t, fx.cp.calls(), "invalid tokens never reach the control plane")
}

func TestTenancy_TunnelsGetTheirOwnTenantsCredentials(t *testing.T) {
	fx := startTenancyProxy(t)
	exp := time.Now().Add(time.Hour)
	tokenA := fx.token(t, "prn_a", exp)
	tokenB := fx.token(t, "prn_b", exp)

	connA, brA := fx.tunnel(t, tokenA)
	connB, brB := fx.tunnel(t, tokenB)
	require.Equal(t, http.StatusOK, fx.get(t, connA, brA).StatusCode)
	headersA := <-fx.seen
	require.Equal(t, http.StatusOK, fx.get(t, connB, brB).StatusCode)
	headersB := <-fx.seen
	require.Equal(t, http.StatusOK, fx.get(t, connA, brA).StatusCode)
	againA := <-fx.seen

	require.Equal(t, "key-for-prn_a", headersA.Get("X-Api-Key"))
	require.Equal(t, tokenA, headersA.Get("X-Tenant-Token"))
	require.Equal(t, "key-for-prn_b", headersB.Get("X-Api-Key"))
	require.Equal(t, tokenB, headersB.Get("X-Tenant-Token"))
	require.Equal(t, "key-for-prn_a", againA.Get("X-Api-Key"))
	for _, h := range []http.Header{headersA, headersB, againA} {
		require.Empty(t, h.Get("Proxy-Authorization"))
	}
	// One fetch per token, each authenticated with that token.
	require.ElementsMatch(t, []string{tokenA, tokenB}, fx.cp.calls())
}

func TestTenancy_ExpiredTokenStopsAnOpenTunnel(t *testing.T) {
	fx := startTenancyProxy(t)
	// Valid now only through the verifier's 30s leeway: it lapses in ~1.5s.
	token := fx.token(t, "prn_a", time.Now().Add(-28500*time.Millisecond))
	conn, br := fx.tunnel(t, token)
	require.Equal(t, http.StatusOK, fx.get(t, conn, br).StatusCode)
	<-fx.seen
	time.Sleep(2 * time.Second)
	resp := fx.get(t, conn, br)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, "tenant_token_expired", resp.Header.Get(tenancyErrorHeader))
}

func TestTenancy_ControlPlaneRefusals(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   int
		code   string
	}{
		// 401 means the control plane refused the proxy itself, which is
		// not the tenant's fault.
		{"proxy refused", http.StatusUnauthorized, http.StatusServiceUnavailable, "tenant_config_unavailable"},
		{"tenant refused", http.StatusForbidden, http.StatusForbidden, "tenant_refused"},
		{"unknown tenant", http.StatusNotFound, http.StatusForbidden, "tenant_refused"},
		{"unavailable", http.StatusBadGateway, http.StatusServiceUnavailable, "tenant_config_unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := startTenancyProxy(t)
			fx.cp.status = tc.status
			resp, _, _ := fx.connect(t, "Bearer "+fx.token(t, "prn_a", time.Now().Add(time.Hour)))
			require.Equal(t, tc.want, resp.StatusCode)
			require.Equal(t, tc.code, resp.Header.Get(tenancyErrorHeader))
		})
	}
}

func TestTenancy_SOCKS5IsRefused(t *testing.T) {
	fx := startTenancyProxy(t)
	conn, err := net.DialTimeout("tcp", fx.tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, []byte{0x05, 0xFF}, reply)
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}

func TestTenancy_AbsoluteFormRequestsAuthenticateEach(t *testing.T) {
	fx := startTenancyProxy(t)
	// Plain HTTP upstream for absolute-form requests.
	seen := make(chan http.Header, 4)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
	}))
	defer plain.Close()
	plainAddr := plain.Listener.Addr().String()
	fx.proxy.transport = &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, plainAddr)
		},
	}
	token := fx.token(t, "prn_a", time.Now().Add(time.Hour))
	send := func(auth string) *http.Response {
		conn, err := net.DialTimeout("tcp", fx.tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		header := ""
		if auth != "" {
			header = "Proxy-Authorization: " + auth + "\r\n"
		}
		_, err = fmt.Fprintf(conn, "GET http://%s/x HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n", tenancyHost, tenancyHost, header)
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		return resp
	}
	resp := send("")
	require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	resp = send("Bearer " + token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	got := <-seen
	require.Equal(t, "key-for-prn_a", got.Get("X-Api-Key"))
	require.Empty(t, got.Get("Proxy-Authorization"))
}

func TestTenancy_DirectListenersRefuseRequests(t *testing.T) {
	fx := startTenancyProxy(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://"+tenancyHost+"/", nil)
	fx.proxy.handleDirectHTTP(rec, req)
	require.Equal(t, http.StatusProxyAuthRequired, rec.Code)
	require.Equal(t, "tenant_token_required", rec.Header().Get(tenancyErrorHeader))
}

func TestTenancy_OpenTunnelsFollowRefreshAndRefusal(t *testing.T) {
	fx := startTenancyProxy(t)
	// A cache that refreshes immediately, so each request refetches.
	fx.proxy.tenancy = tenancy.New(tenancy.Options{
		Verifier:          tenancy.NewVerifier([]ed25519.PublicKey{fx.key.Public().(ed25519.PublicKey)}, tenancyIssuer, tenancyAudience),
		URL:               fx.cp.server.URL,
		ControlPlaneToken: tenancyCPToken,
		FreshFor:          time.Nanosecond,
		StaleFor:          time.Nanosecond,
		Build:             buildTestPipeline(t),
		Logger:            testLogger(),
	})
	token := fx.token(t, "prn_a", time.Now().Add(time.Hour))
	conn, br := fx.tunnel(t, token)
	require.Equal(t, http.StatusOK, fx.get(t, conn, br).StatusCode)
	<-fx.seen

	// Refused by the control plane: the open tunnel stops serving on its
	// next request.
	fx.cp.mu.Lock()
	fx.cp.status = http.StatusForbidden
	fx.cp.mu.Unlock()
	resp := fx.get(t, conn, br)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.Equal(t, "tenant_refused", resp.Header.Get(tenancyErrorHeader))
}

// headerSpy records the Proxy-Authorization header each request reaching
// the pipeline carries.
type headerSpy struct {
	mu   sync.Mutex
	seen []string
}

func (h *headerSpy) Name() string { return "header-spy" }

func (h *headerSpy) TransformRequest(_ context.Context, _ *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	h.mu.Lock()
	h.seen = append(h.seen, req.Header.Get("Proxy-Authorization"))
	h.mu.Unlock()
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (h *headerSpy) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func TestTenancy_PipelinesNeverSeeTheTenantToken(t *testing.T) {
	fx := startTenancyProxy(t)
	spy := &headerSpy{}
	fx.proxy.tenancy = tenancy.New(tenancy.Options{
		Verifier:          tenancy.NewVerifier([]ed25519.PublicKey{fx.key.Public().(ed25519.PublicKey)}, tenancyIssuer, tenancyAudience),
		URL:               fx.cp.server.URL,
		ControlPlaneToken: tenancyCPToken,
		FreshFor:          time.Minute,
		StaleFor:          10 * time.Minute,
		Build:             buildTestPipeline(t, spy),
		Logger:            testLogger(),
	})
	conn, br := fx.tunnel(t, fx.token(t, "prn_a", time.Now().Add(time.Hour)))
	require.Equal(t, http.StatusOK, fx.get(t, conn, br).StatusCode)
	<-fx.seen
	spy.mu.Lock()
	defer spy.mu.Unlock()
	require.Len(t, spy.seen, 2, "the CONNECT check and the inner request")
	for _, value := range spy.seen {
		require.Empty(t, value)
	}
}
