package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// --- test doubles ---

// staticSource implements secrets.Source with a fixed value or error.
type staticSource struct {
	name  string
	value string
	err   error
	calls atomic.Int64
}

func (s *staticSource) Name() string { return s.name }
func (s *staticSource) Get(context.Context) (string, error) {
	s.calls.Add(1)
	return s.value, s.err
}

func staticBuilder(src secrets.Source) sourceBuilder {
	return func(yaml.Node, *slog.Logger) (secrets.Source, error) { return src, nil }
}

// mapBuilder dispatches each credential node to a source keyed by the node's
// "var" field, so discrete-source tests can give every field its own value.
func mapBuilder(srcs map[string]secrets.Source) sourceBuilder {
	return func(n yaml.Node, _ *slog.Logger) (secrets.Source, error) {
		var c struct {
			Var string `yaml:"var"`
		}
		if err := n.Decode(&c); err != nil {
			return nil, err
		}
		src, ok := srcs[c.Var]
		if !ok {
			return nil, fmt.Errorf("no test source for var %q", c.Var)
		}
		return src, nil
	}
}

// tokenServer is a fake OAuth2 token endpoint. It counts requests and records
// each request's form so tests can assert on the exchange.
type tokenServer struct {
	*httptest.Server
	mu      sync.Mutex
	calls   int
	forms   []url.Values
	headers []http.Header
}

func (ts *tokenServer) Calls() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.calls
}

func (ts *tokenServer) LastForm() url.Values {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.forms[len(ts.forms)-1]
}

func (ts *tokenServer) LastHeaders() http.Header {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.headers[len(ts.headers)-1]
}

// newTokenServer serves the OAuth2 token endpoint. respond decides the HTTP
// status and JSON body per request; pass nil for the default success
// response that mints "minted-token".
func newTokenServer(t *testing.T, respond func(form url.Values) (int, map[string]any)) *tokenServer {
	t.Helper()
	if respond == nil {
		respond = func(url.Values) (int, map[string]any) {
			return http.StatusOK, map[string]any{
				"access_token": "minted-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			}
		}
	}
	ts := &tokenServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		ts.mu.Lock()
		ts.calls++
		ts.forms = append(ts.forms, r.PostForm)
		ts.headers = append(ts.headers, r.Header.Clone())
		ts.mu.Unlock()
		status, body := respond(r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// ccBuilder is a source builder for a client_credentials entry whose discrete
// client_id and client_secret resolve to fixed test values.
func ccBuilder() sourceBuilder {
	return mapBuilder(map[string]secrets.Source{
		"CID":     &staticSource{name: "cid", value: "test-client-id"},
		"CSECRET": &staticSource{name: "cs", value: "test-client-secret"},
	})
}

// --- generic helpers ---

func yamlFromString(t *testing.T, src string) yaml.Node {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &node))
	return *node.Content[0]
}

func newRequest(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, rawURL, nil)
	require.NoError(t, err)
	return r
}

func newContext() *transform.TransformContext {
	return &transform.TransformContext{Mode: transform.ModeMITM}
}

// buildTransformWith decodes cfgYAML and builds the transform with a custom
// source builder, so tests never reach a real secret backend.
func buildTransformWith(t *testing.T, cfgYAML string, build sourceBuilder) *OAuth {
	t.Helper()
	var c config
	node := yamlFromString(t, cfgYAML)
	require.NoError(t, node.Decode(&c))
	o, err := newFromConfig(c, slog.Default(), build)
	require.NoError(t, err)
	return o
}

type tokenJSON struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func decodeBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	require.NotNil(t, resp)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return body
}

// --- validation ---

func TestValidation(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantError string
	}{
		{
			name:      "empty tokens",
			yaml:      `tokens: []`,
			wantError: "at least one entry in \"tokens\"",
		},
		{
			name: "unknown grant",
			yaml: `
tokens:
  - grant: magic_beans
    client_id: {type: env, var: CID}
    rules:
      - host: "example.com"
`,
			wantError: "\"grant\" must be one of",
		},
		{
			name: "refresh_token without token_endpoint",
			yaml: `
tokens:
  - grant: refresh_token
    refresh_token: {type: env, var: RT}
    client_id: {type: env, var: CID}
    rules:
      - host: "example.com"
`,
			wantError: "refresh_token grant requires \"token_endpoint\"",
		},
		{
			name: "client_credentials without token_endpoint",
			yaml: `
tokens:
  - grant: client_credentials
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    rules:
      - host: "example.com"
`,
			wantError: "client_credentials grant requires \"token_endpoint\"",
		},
		{
			name: "missing rules",
			yaml: `
tokens:
  - grant: client_credentials
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "https://t.example.com/token"
`,
			wantError: "at least one entry in \"rules\"",
		},
		{
			name: "refresh_token missing client_id",
			yaml: `
tokens:
  - grant: refresh_token
    refresh_token: {type: env, var: RT}
    token_endpoint: "https://t.example.com/token"
    rules:
      - host: "example.com"
`,
			wantError: "requires \"client_id\"",
		},
		{
			name: "refresh_token missing refresh_token",
			yaml: `
tokens:
  - grant: refresh_token
    client_id: {type: env, var: CID}
    token_endpoint: "https://t.example.com/token"
    rules:
      - host: "example.com"
`,
			wantError: "requires \"refresh_token\"",
		},
		{
			name: "client_credentials missing client_secret",
			yaml: `
tokens:
  - grant: client_credentials
    client_id: {type: env, var: CID}
    token_endpoint: "https://t.example.com/token"
    rules:
      - host: "example.com"
`,
			wantError: "requires \"client_id\" and \"client_secret\"",
		},
		{
			name: "password missing username",
			yaml: `
tokens:
  - grant: password
    password: {type: env, var: PW}
    client_id: {type: env, var: CID}
    token_endpoint: "https://t.example.com/token"
    rules:
      - host: "example.com"
`,
			wantError: "password grant requires \"username\" and \"password\"",
		},
		{
			name: "password missing client_id",
			yaml: `
tokens:
  - grant: password
    username: {type: env, var: USER}
    password: {type: env, var: PW}
    token_endpoint: "https://t.example.com/token"
    rules:
      - host: "example.com"
`,
			wantError: "password grant requires \"client_id\"",
		},
		{
			name: "jwt_bearer missing audience",
			yaml: `
tokens:
  - grant: jwt_bearer
    issuer:      {type: env, var: ISS}
    subject:     {type: env, var: SUB}
    private_key: {type: env, var: PK}
    token_endpoint: "https://t.example.com/token"
    rules:
      - host: "example.com"
`,
			wantError: "jwt_bearer grant requires \"audience\"",
		},
		{
			name: "jwt_bearer missing issuer",
			yaml: `
tokens:
  - grant: jwt_bearer
    subject:     {type: env, var: SUB}
    private_key: {type: env, var: PK}
    audience: "aud.example.com"
    token_endpoint: "https://t.example.com/token"
    rules:
      - host: "example.com"
`,
			wantError: "jwt_bearer grant requires \"issuer\"",
		},
		{
			name: "jwt_bearer missing subject",
			yaml: `
tokens:
  - grant: jwt_bearer
    issuer:      {type: env, var: ISS}
    private_key: {type: env, var: PK}
    audience: "aud.example.com"
    token_endpoint: "https://t.example.com/token"
    rules:
      - host: "example.com"
`,
			wantError: "jwt_bearer grant requires \"subject\"",
		},
		{
			name: "jwt_bearer missing private_key",
			yaml: `
tokens:
  - grant: jwt_bearer
    issuer:  {type: env, var: ISS}
    subject: {type: env, var: SUB}
    audience: "aud.example.com"
    token_endpoint: "https://t.example.com/token"
    rules:
      - host: "example.com"
`,
			wantError: "jwt_bearer grant requires \"private_key\"",
		},
		{
			name: "jwt_bearer missing token_endpoint",
			yaml: `
tokens:
  - grant: jwt_bearer
    issuer:      {type: env, var: ISS}
    subject:     {type: env, var: SUB}
    private_key: {type: env, var: PK}
    audience: "aud.example.com"
    rules:
      - host: "example.com"
`,
			wantError: "jwt_bearer grant requires \"token_endpoint\"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c config
			node := yamlFromString(t, tc.yaml)
			require.NoError(t, node.Decode(&c))
			_, err := newFromConfig(c, slog.Default(), staticBuilder(&staticSource{}))
			require.ErrorContains(t, err, tc.wantError)
		})
	}
}

// --- refresh_token grant ---

func TestRefreshTokenGrant_InjectsBearer(t *testing.T) {
	srv := newTokenServer(t, nil)
	o := buildTransformWith(t, `
tokens:
  - grant: refresh_token
    refresh_token: {type: env, var: RT}
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"]
    rules:
      - host: "gmail.googleapis.com"
`, mapBuilder(map[string]secrets.Source{
		"RT":      &staticSource{name: "rt", value: "discrete-refresh-token"},
		"CID":     &staticSource{name: "cid", value: "discrete-client-id"},
		"CSECRET": &staticSource{name: "cs", value: "discrete-client-secret"},
	}))

	req := newRequest(t, http.MethodGet, "https://gmail.googleapis.com/gmail/v1/users/me/messages")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))

	form := srv.LastForm()
	require.Equal(t, "refresh_token", form.Get("grant_type"))
	require.Equal(t, "discrete-refresh-token", form.Get("refresh_token"))
	require.Equal(t, "discrete-client-id", form.Get("client_id"))
	require.Equal(t, "discrete-client-secret", form.Get("client_secret"), "client auth must be in the form body")
}

// A public client has no client_secret: the field is omitted entirely.
func TestRefreshTokenGrant_PublicClient(t *testing.T) {
	srv := newTokenServer(t, nil)
	o := buildTransformWith(t, `
tokens:
  - grant: refresh_token
    refresh_token: {type: env, var: RT}
    client_id: {type: env, var: CID}
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "gmail.googleapis.com"
`, mapBuilder(map[string]secrets.Source{
		"RT":  &staticSource{name: "rt", value: "discrete-refresh-token"},
		"CID": &staticSource{name: "cid", value: "discrete-client-id"},
	}))

	req := newRequest(t, http.MethodGet, "https://gmail.googleapis.com/v1/x")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))
	require.Empty(t, srv.LastForm().Get("client_secret"), "a public client sends no client_secret")
}

// --- client_credentials grant ---

func TestClientCredentialsGrant_InjectsBearer(t *testing.T) {
	srv := newTokenServer(t, nil)
	o := buildTransformWith(t, `
tokens:
  - grant: client_credentials
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    scopes: ["api.read"]
    rules:
      - host: "api.example.com"
`, ccBuilder())

	req := newRequest(t, http.MethodGet, "https://api.example.com/v1/things")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))

	form := srv.LastForm()
	require.Equal(t, "client_credentials", form.Get("grant_type"))
	require.Equal(t, "test-client-id", form.Get("client_id"))
	require.Equal(t, "test-client-secret", form.Get("client_secret"))
	require.Equal(t, "api.read", form.Get("scope"))
}

// --- caching, matching, injection behavior ---

func TestCachesTokenAcrossRequests(t *testing.T) {
	srv := newTokenServer(t, nil)
	o := buildTransformWith(t, `
tokens:
  - grant: client_credentials
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "api.example.com"
`, ccBuilder())

	for i := 0; i < 5; i++ {
		req := newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
		_, err := o.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))
	}
	require.Equal(t, 1, srv.Calls(), "token should be minted once and cached")
}

func TestConcurrentRequestsTriggerSingleRefresh(t *testing.T) {
	srv := newTokenServer(t, nil)
	o := buildTransformWith(t, `
tokens:
  - grant: client_credentials
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "api.example.com"
`, ccBuilder())

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
			_, err := o.TransformRequest(context.Background(), newContext(), req)
			require.NoError(t, err)
		}()
	}
	wg.Wait()
	require.Equal(t, 1, srv.Calls(), "concurrent requests must single-flight the exchange")
}

// The cached token source outlives the request that built it. Once that
// request's context is canceled, later refreshes must still reach the token
// endpoint instead of failing with "context canceled".
func TestRefreshAfterFirstRequestContextCanceled(t *testing.T) {
	sources := map[string]secrets.Source{
		"RT":      &staticSource{name: "rt", value: "test-refresh-token"},
		"CID":     &staticSource{name: "cid", value: "test-client-id"},
		"CSECRET": &staticSource{name: "cs", value: "test-client-secret"},
		"TENANT":  &staticSource{name: "t", value: "acme"},
	}
	cases := []struct {
		name  string
		entry string
	}{
		{
			name: "refresh_token",
			entry: `
  - grant: refresh_token
    refresh_token: {type: env, var: RT}
    client_id:     {type: env, var: CID}`,
		},
		{
			name: "client_credentials",
			entry: `
  - grant: client_credentials
    client_id:     {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}`,
		},
		{
			name: "client_credentials with token endpoint headers",
			entry: `
  - grant: client_credentials
    client_id:     {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint_headers:
      x-tenant: {type: env, var: TENANT}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// expires_in 1 is inside oauth2's 10s expiry delta, so every request refreshes.
			srv := newTokenServer(t, func(url.Values) (int, map[string]any) {
				return http.StatusOK, map[string]any{
					"access_token": "minted-token",
					"token_type":   "Bearer",
					"expires_in":   1,
				}
			})
			o := buildTransformWith(t, "tokens:"+tc.entry+`
    token_endpoint: "`+srv.URL+`/token"
    require: true
    rules:
      - host: "api.example.com"
`, mapBuilder(sources))

			first, cancel := context.WithCancel(context.Background())
			req := newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
			res, err := o.TransformRequest(first, newContext(), req)
			require.NoError(t, err)
			require.Equal(t, transform.ActionContinue, res.Action)
			cancel()

			req = newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
			res, err = o.TransformRequest(context.Background(), newContext(), req)
			require.NoError(t, err)
			require.Equal(t, transform.ActionContinue, res.Action)
			require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))
			require.Equal(t, 2, srv.Calls(), "the expired token must be refreshed")
		})
	}
}

func TestNoMatchingEntryPassesThrough(t *testing.T) {
	srv := newTokenServer(t, nil)
	o := buildTransformWith(t, `
tokens:
  - grant: client_credentials
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "api.example.com"
`, ccBuilder())

	req := newRequest(t, http.MethodGet, "https://other.example.org/v1/x")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Empty(t, req.Header.Get("Authorization"))
	require.Equal(t, 0, srv.Calls())
}

func TestOverwritesExistingAuthorizationHeader(t *testing.T) {
	srv := newTokenServer(t, nil)
	o := buildTransformWith(t, `
tokens:
  - grant: client_credentials
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "api.example.com"
`, ccBuilder())

	req := newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
	req.Header.Set("Authorization", "Bearer client-supplied-token")
	_, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))
}

// The first entry whose rules match wins, in config order.
func TestFirstMatchingEntryWins(t *testing.T) {
	srv := newTokenServer(t, func(form url.Values) (int, map[string]any) {
		return http.StatusOK, map[string]any{
			"access_token": "token-for-" + form.Get("scope"),
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
	})
	o := buildTransformWith(t, `
tokens:
  - grant: client_credentials
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    scopes: ["first"]
    rules:
      - host: "*.example.com"
  - grant: client_credentials
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    scopes: ["second"]
    rules:
      - host: "api.example.com"
`, ccBuilder())

	req := newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
	_, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, "Bearer token-for-first", req.Header.Get("Authorization"))
}

// --- token endpoint stubbing ---

func TestStubsConfiguredTokenEndpoint(t *testing.T) {
	srv := newTokenServer(t, nil)
	tokenURL := srv.URL + "/token"

	// rules target the API host on purpose: stubbing must not depend on the
	// rules matching the token endpoint.
	o := buildTransformWith(t, `
tokens:
  - grant: client_credentials
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+tokenURL+`"
    scopes: ["api.read"]
    rules:
      - host: "api.example.com"
`, ccBuilder())

	req := newRequest(t, http.MethodPost, tokenURL)
	tctx := newContext()
	res, err := o.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionStub, res.Action)

	var decoded tokenJSON
	require.NoError(t, json.Unmarshal(decodeBody(t, res.Response), &decoded))
	require.Equal(t, stubAccessToken, decoded.AccessToken)
	require.Equal(t, "Bearer", decoded.TokenType)
	require.Equal(t, 3600, decoded.ExpiresIn)
	require.Equal(t, "oauth2_token_endpoint", tctx.DrainAnnotations()["stubbed"])
	require.Equal(t, 0, srv.Calls(), "the real token endpoint must not be hit when stubbing")
}

// A non-token path on the token endpoint host is not stubbed.
func TestDoesNotStubOtherPaths(t *testing.T) {
	srv := newTokenServer(t, nil)

	o := buildTransformWith(t, `
tokens:
  - grant: client_credentials
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    scopes: ["s"]
    rules:
      - host: "api.example.com"
`, ccBuilder())

	req := newRequest(t, http.MethodGet, srv.URL+"/revoke")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action, "non-token path falls through")
}

// --- failure handling ---

func TestInvalidGrantFails502(t *testing.T) {
	srv := newTokenServer(t, func(url.Values) (int, map[string]any) {
		return http.StatusBadRequest, map[string]any{
			"error":             "invalid_grant",
			"error_description": "Token has been expired or revoked.",
		}
	})
	o := buildTransformWith(t, `
tokens:
  - grant: refresh_token
    require: true
    refresh_token: {type: env, var: RT}
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "gmail.googleapis.com"
`, mapBuilder(map[string]secrets.Source{
		"RT":      &staticSource{name: "rt", value: "test-refresh-token"},
		"CID":     &staticSource{name: "cid", value: "test-client-id"},
		"CSECRET": &staticSource{name: "cs", value: "test-client-secret"},
	}))

	req := newRequest(t, http.MethodGet, "https://gmail.googleapis.com/v1/x")
	tctx := newContext()
	res, err := o.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, http.StatusBadGateway, res.Response.StatusCode)
	require.Empty(t, req.Header.Get("Authorization"), "an unauthenticated request must not be forwarded")

	body := decodeBody(t, res.Response)
	require.Contains(t, string(body), "oauth_token failed to mint")

	annotations := tctx.DrainAnnotations()
	require.Equal(t, "invalid_grant", annotations["error"])
	require.Equal(t, "token_unavailable", annotations["rejected"])
}

func TestCredentialUnavailableFails502(t *testing.T) {
	o := buildTransformWith(t, `
tokens:
  - grant: refresh_token
    require: true
    refresh_token: {type: env, var: RT}
    client_id: {type: env, var: CID}
    token_endpoint: "https://oauth2.example.com/token"
    rules:
      - host: "gmail.googleapis.com"
`, mapBuilder(map[string]secrets.Source{
		"RT":  &staticSource{name: "rt", err: io.ErrUnexpectedEOF},
		"CID": &staticSource{name: "cid", value: "test-client-id"},
	}))

	req := newRequest(t, http.MethodGet, "https://gmail.googleapis.com/v1/x")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, http.StatusBadGateway, res.Response.StatusCode)
}

// By default (require unset) a mint failure must not take down the request:
// the proxy forwards it without a token instead of rejecting with a 502.
func TestMintFailureForwardsWithoutTokenByDefault(t *testing.T) {
	srv := newTokenServer(t, func(url.Values) (int, map[string]any) {
		return http.StatusBadRequest, map[string]any{
			"error":             "invalid_grant",
			"error_description": "Token has been expired or revoked.",
		}
	})
	o := buildTransformWith(t, `
tokens:
  - grant: refresh_token
    refresh_token: {type: env, var: RT}
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "gmail.googleapis.com"
`, mapBuilder(map[string]secrets.Source{
		"RT":      &staticSource{name: "rt", value: "test-refresh-token"},
		"CID":     &staticSource{name: "cid", value: "test-client-id"},
		"CSECRET": &staticSource{name: "cs", value: "test-client-secret"},
	}))

	req := newRequest(t, http.MethodGet, "https://gmail.googleapis.com/v1/x")
	tctx := newContext()
	res, err := o.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action, "request is forwarded, not rejected")
	require.Nil(t, res.Response, "no synthetic failure response on fail-open")
	require.Empty(t, req.Header.Get("Authorization"), "no token is injected when minting fails")

	annotations := tctx.DrainAnnotations()
	require.Equal(t, "invalid_grant", annotations["error"])
	require.Equal(t, "token_unavailable", annotations["skipped"])
	require.NotContains(t, annotations, "rejected")
}

// A credential source that errors also fails open by default.
func TestCredentialUnavailableForwardsByDefault(t *testing.T) {
	o := buildTransformWith(t, `
tokens:
  - grant: refresh_token
    refresh_token: {type: env, var: RT}
    client_id: {type: env, var: CID}
    token_endpoint: "https://oauth2.example.com/token"
    rules:
      - host: "gmail.googleapis.com"
`, mapBuilder(map[string]secrets.Source{
		"RT":  &staticSource{name: "rt", err: io.ErrUnexpectedEOF},
		"CID": &staticSource{name: "cid", value: "test-client-id"},
	}))

	req := newRequest(t, http.MethodGet, "https://gmail.googleapis.com/v1/x")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Empty(t, req.Header.Get("Authorization"))
}

// --- password grant ---

func TestPasswordGrant_InjectsBearer(t *testing.T) {
	srv := newTokenServer(t, nil)
	o := buildTransformWith(t, `
tokens:
  - grant: password
    username:      {type: env, var: USER}
    password:      {type: env, var: PW}
    client_id:     {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    scopes: ["read"]
    rules:
      - host: "api.alpha-sense.com"
`, mapBuilder(map[string]secrets.Source{
		"USER":    &staticSource{name: "u", value: "alice"},
		"PW":      &staticSource{name: "p", value: "s3cret"},
		"CID":     &staticSource{name: "cid", value: "the-client-id"},
		"CSECRET": &staticSource{name: "cs", value: "the-client-secret"},
	}))

	req := newRequest(t, http.MethodPost, "https://api.alpha-sense.com/gql")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))

	form := srv.LastForm()
	require.Equal(t, "password", form.Get("grant_type"))
	require.Equal(t, "alice", form.Get("username"))
	require.Equal(t, "s3cret", form.Get("password"))
	require.Equal(t, "the-client-id", form.Get("client_id"))
	require.Equal(t, "the-client-secret", form.Get("client_secret"))
	require.Equal(t, "read", form.Get("scope"))
}

// A password client without a client_secret (public client) omits the form field.
func TestPasswordGrant_PublicClient(t *testing.T) {
	srv := newTokenServer(t, nil)
	o := buildTransformWith(t, `
tokens:
  - grant: password
    username:  {type: env, var: USER}
    password:  {type: env, var: PW}
    client_id: {type: env, var: CID}
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "api.example.com"
`, mapBuilder(map[string]secrets.Source{
		"USER": &staticSource{name: "u", value: "alice"},
		"PW":   &staticSource{name: "p", value: "s3cret"},
		"CID":  &staticSource{name: "cid", value: "the-client-id"},
	}))

	req := newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
	_, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Empty(t, srv.LastForm().Get("client_secret"))
}

// --- token_endpoint_headers ---

func TestTokenEndpointHeaders_SentOnMint(t *testing.T) {
	srv := newTokenServer(t, nil)
	o := buildTransformWith(t, `
tokens:
  - grant: password
    username:  {type: env, var: USER}
    password:  {type: env, var: PW}
    client_id: {type: env, var: CID}
    token_endpoint: "`+srv.URL+`/token"
    token_endpoint_headers:
      x-api-key: {type: env, var: APIKEY}
    rules:
      - host: "api.alpha-sense.com"
`, mapBuilder(map[string]secrets.Source{
		"USER":   &staticSource{name: "u", value: "alice"},
		"PW":     &staticSource{name: "p", value: "s3cret"},
		"CID":    &staticSource{name: "cid", value: "the-client-id"},
		"APIKEY": &staticSource{name: "k", value: "venue-api-key"},
	}))

	req := newRequest(t, http.MethodPost, "https://api.alpha-sense.com/gql")
	_, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)

	// httptest can't observe wire-level casing (the server parses through
	// textproto, which canonicalizes). Here we just confirm the value reached
	// the token endpoint at all.
	require.Equal(t, "venue-api-key", srv.LastHeaders().Get("X-Api-Key"))
	// The inbound request itself must not have received the header.
	require.Empty(t, req.Header.Get("X-Api-Key"))
}

// Endpoint headers also work for other grants — verify with client_credentials.
func TestTokenEndpointHeaders_ClientCredentials(t *testing.T) {
	srv := newTokenServer(t, nil)
	o := buildTransformWith(t, `
tokens:
  - grant: client_credentials
    client_id:     {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    token_endpoint_headers:
      x-tenant: {type: env, var: TENANT}
    rules:
      - host: "api.example.com"
`, mapBuilder(map[string]secrets.Source{
		"CID":     &staticSource{name: "cid", value: "cid"},
		"CSECRET": &staticSource{name: "cs", value: "cs"},
		"TENANT":  &staticSource{name: "t", value: "acme"},
	}))

	req := newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
	_, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, "acme", srv.LastHeaders().Get("X-Tenant"))
}

// --- jwt_bearer grant ---

// pemRSAKey generates an RSA private key and returns it both as a *rsa.PrivateKey
// (for verifying the signature in the test) and as PEM bytes (to feed into the
// transform as the private_key secret value).
func pemRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return key, string(pem.EncodeToMemory(pemBlock))
}

// parseAssertion splits a compact-serialized JWS into decoded header and claim
// maps plus the signing input and signature bytes — enough to verify both the
// claim shape and the RS256 signature without pulling in a JWT library.
func parseAssertion(t *testing.T, assertion string) (header, claims map[string]any, signingInput []byte, sig []byte) {
	t.Helper()
	parts := strings.Split(assertion, ".")
	require.Len(t, parts, 3, "assertion must have three dot-separated segments")
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	require.NoError(t, json.Unmarshal(claimsBytes, &claims))
	signingInput = []byte(parts[0] + "." + parts[1])
	return header, claims, signingInput, sig
}

func TestJWTBearerGrant_InjectsBearer(t *testing.T) {
	key, pemKey := pemRSAKey(t)

	var observedAssertion string
	srv := newTokenServer(t, func(form url.Values) (int, map[string]any) {
		observedAssertion = form.Get("assertion")
		return http.StatusOK, map[string]any{
			"access_token": "minted-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
	})

	o := buildTransformWith(t, `
tokens:
  - grant: jwt_bearer
    issuer:         {type: env, var: ISS}
    subject:        {type: env, var: SUB}
    private_key:    {type: env, var: PK}
    private_key_id: {type: env, var: KID}
    audience: "account.docusign.com"
    token_endpoint: "`+srv.URL+`/token"
    scopes: ["signature", "impersonation"]
    rules:
      - host: "*.docusign.net"
`, mapBuilder(map[string]secrets.Source{
		"ISS": &staticSource{name: "iss", value: "integration-key"},
		"SUB": &staticSource{name: "sub", value: "user-guid"},
		"PK":  &staticSource{name: "pk", value: pemKey},
		"KID": &staticSource{name: "kid", value: "key-1"},
	}))

	req := newRequest(t, http.MethodGet, "https://demo.docusign.net/restapi/v2.1/accounts/x/users")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))

	form := srv.LastForm()
	require.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", form.Get("grant_type"))
	require.NotEmpty(t, observedAssertion)

	header, claims, signingInput, sig := parseAssertion(t, observedAssertion)
	require.Equal(t, "RS256", header["alg"])
	require.Equal(t, "JWT", header["typ"])
	require.Equal(t, "key-1", header["kid"])
	require.Equal(t, "integration-key", claims["iss"])
	require.Equal(t, "user-guid", claims["sub"])
	require.Equal(t, "account.docusign.com", claims["aud"])
	require.Equal(t, "signature impersonation", claims["scope"])
	require.NotZero(t, claims["iat"])
	require.NotZero(t, claims["exp"])

	digest := sha256.Sum256(signingInput)
	require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig),
		"assertion signature must verify against the registered public key")
}

// A jwt_bearer entry without a private_key_id omits the JWT kid header.
func TestJWTBearerGrant_NoKeyID(t *testing.T) {
	_, pemKey := pemRSAKey(t)

	var observedAssertion string
	srv := newTokenServer(t, func(form url.Values) (int, map[string]any) {
		observedAssertion = form.Get("assertion")
		return http.StatusOK, map[string]any{
			"access_token": "minted-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
	})

	o := buildTransformWith(t, `
tokens:
  - grant: jwt_bearer
    issuer:      {type: env, var: ISS}
    subject:     {type: env, var: SUB}
    private_key: {type: env, var: PK}
    audience: "account.docusign.com"
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "*.docusign.net"
`, mapBuilder(map[string]secrets.Source{
		"ISS": &staticSource{name: "iss", value: "integration-key"},
		"SUB": &staticSource{name: "sub", value: "user-guid"},
		"PK":  &staticSource{name: "pk", value: pemKey},
	}))

	req := newRequest(t, http.MethodGet, "https://demo.docusign.net/restapi/v2.1/x")
	_, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	header, _, _, _ := parseAssertion(t, observedAssertion)
	_, ok := header["kid"]
	require.False(t, ok, "kid must be omitted when private_key_id is not set")
}

// Rotating the private_key value invalidates the cached token source so the
// next mint signs with the new key. Other credentials behave the same; this
// guards the jwt_bearer-specific wiring through resolveCredentials.
func TestJWTBearerGrant_KeyRotationRebuildsTokenSource(t *testing.T) {
	keyA, pemA := pemRSAKey(t)
	keyB, pemB := pemRSAKey(t)

	var observedAssertion string
	mintCount := 0
	srv := newTokenServer(t, func(form url.Values) (int, map[string]any) {
		mintCount++
		observedAssertion = form.Get("assertion")
		return http.StatusOK, map[string]any{
			"access_token": fmt.Sprintf("minted-token-%d", mintCount),
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
	})

	pkSource := &staticSource{name: "pk", value: pemA}
	o := buildTransformWith(t, `
tokens:
  - grant: jwt_bearer
    issuer:      {type: env, var: ISS}
    subject:     {type: env, var: SUB}
    private_key: {type: env, var: PK}
    audience: "account.docusign.com"
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "*.docusign.net"
`, mapBuilder(map[string]secrets.Source{
		"ISS": &staticSource{name: "iss", value: "integration-key"},
		"SUB": &staticSource{name: "sub", value: "user-guid"},
		"PK":  pkSource,
	}))

	req := newRequest(t, http.MethodGet, "https://demo.docusign.net/v1/x")
	_, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, "Bearer minted-token-1", req.Header.Get("Authorization"))

	_, _, signingInput, sig := parseAssertion(t, observedAssertion)
	digest := sha256.Sum256(signingInput)
	require.NoError(t, rsa.VerifyPKCS1v15(&keyA.PublicKey, crypto.SHA256, digest[:], sig))

	pkSource.value = pemB
	req2 := newRequest(t, http.MethodGet, "https://demo.docusign.net/v1/y")
	_, err = o.TransformRequest(context.Background(), newContext(), req2)
	require.NoError(t, err)
	require.Equal(t, "Bearer minted-token-2", req2.Header.Get("Authorization"),
		"rotating the private key must rebuild the token source and force a remint")

	_, _, signingInput, sig = parseAssertion(t, observedAssertion)
	digest = sha256.Sum256(signingInput)
	require.NoError(t, rsa.VerifyPKCS1v15(&keyB.PublicKey, crypto.SHA256, digest[:], sig))
}

// --- factory end-to-end through the real secrets package ---

func TestFactory_EndToEnd(t *testing.T) {
	srv := newTokenServer(t, nil)
	t.Setenv("OAUTH_CLIENT_ID", "test-client-id")
	t.Setenv("OAUTH_CLIENT_SECRET", "test-client-secret")

	tr, err := factory(yamlFromString(t, `
tokens:
  - grant: client_credentials
    client_id:
      type: env
      var: OAUTH_CLIENT_ID
    client_secret:
      type: env
      var: OAUTH_CLIENT_SECRET
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "api.example.com"
`), slog.Default())
	require.NoError(t, err)

	req := newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
	res, err := tr.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))
}
