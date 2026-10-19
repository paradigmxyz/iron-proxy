package oauth

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"net/http"
	"sort"

	"github.com/zeebo/blake3"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/jwt"

	"github.com/ironsh/iron-proxy/internal/headers"
)

// mint returns a cached or freshly minted access token for the entry.
func (e *tokenEntry) mint(ctx context.Context) (string, error) {
	ts, err := e.tokenSourceFor(ctx)
	if err != nil {
		return "", err
	}
	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("minting %s access token: %w", e.grant, err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("%s token endpoint returned an empty access_token", e.grant)
	}
	return tok.AccessToken, nil
}

// tokenSourceFor returns the entry's oauth2.TokenSource, rebuilding it when any
// credential value has changed since it was last built. The returned source
// caches the access token and single-flights concurrent refreshes.
func (e *tokenEntry) tokenSourceFor(ctx context.Context) (oauth2.TokenSource, error) {
	// Sources are read outside the lock: each has its own ttl cache, so this is
	// cheap and returns stable values within the ttl window. Credential bytes
	// stream straight into the hasher so plaintext secrets aren't held in an
	// intermediate buffer.
	h := blake3.New()
	vals, err := e.resolveCredentials(ctx, h)
	if err != nil {
		return nil, err
	}
	headers, err := e.resolveEndpointHeaders(ctx, h)
	if err != nil {
		return nil, err
	}
	var fingerprint [32]byte
	copy(fingerprint[:], h.Sum(nil))

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tokenSource != nil && fingerprint == e.fingerprint {
		return e.tokenSource, nil
	}
	// The token source is cached and refreshes during later requests, so it
	// keeps this request's values but not its cancellation.
	tsCtx := context.WithoutCancel(ctx)
	if len(headers) > 0 {
		tsCtx = context.WithValue(tsCtx, oauth2.HTTPClient, newHeaderInjectingClient(headers))
	}
	ts, err := buildTokenSource(tsCtx, e.grant, vals, e.scopes, e.cfgEndpoint, e.audience)
	if err != nil {
		return nil, err
	}
	e.tokenSource = ts
	e.fingerprint = fingerprint
	return ts, nil
}

// resolveCredentials fetches every credential source for the entry, returns
// the resolved values keyed by field, and streams each key/value pair into the
// given hasher so the caller can derive a fingerprint that changes whenever
// any value does.
func (e *tokenEntry) resolveCredentials(ctx context.Context, h hash.Hash) (map[string]string, error) {
	keys := make([]string, 0, len(e.sources))
	for k := range e.sources {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	vals := make(map[string]string, len(e.sources))
	for _, k := range keys {
		v, err := e.sources[k].Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("loading %s from %q: %w", k, e.sources[k].Name(), err)
		}
		vals[k] = v
		writeFingerprintField(h, k, v)
	}
	return vals, nil
}

// resolveEndpointHeaders mirrors resolveCredentials for the token-endpoint
// header sources. A length-prefixed section marker precedes its fields so a
// header named the same as a credential field can't collide with it.
func (e *tokenEntry) resolveEndpointHeaders(ctx context.Context, h hash.Hash) (map[string]string, error) {
	if len(e.endpointHeaderSources) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(e.endpointHeaderSources))
	for k := range e.endpointHeaderSources {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string]string, len(e.endpointHeaderSources))
	writeFingerprintBytes(h, []byte("endpoint_headers"))
	for _, k := range keys {
		v, err := e.endpointHeaderSources[k].Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("loading token_endpoint_headers[%q] from %q: %w", k, e.endpointHeaderSources[k].Name(), err)
		}
		out[k] = v
		writeFingerprintField(h, k, v)
	}
	return out, nil
}

// writeFingerprintField streams a key/value pair into the hasher with explicit
// uint32 length prefixes. Length prefixing rules out canonicalization
// collisions regardless of what bytes a secret source returns. hash.Hash
// writes never fail, so the errors are dropped.
func writeFingerprintField(h hash.Hash, k, v string) {
	writeFingerprintBytes(h, []byte(k))
	writeFingerprintBytes(h, []byte(v))
}

func writeFingerprintBytes(h hash.Hash, b []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(b)
}

// headerInjectingTransport sets configured headers on every request before
// delegating to the underlying RoundTripper. Used to decorate token-endpoint
// POSTs with vendor-specific headers like x-api-key.
type headerInjectingTransport struct {
	headers map[string]string
	base    http.RoundTripper
}

func (t *headerInjectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone before mutating: the oauth2 lib may retry, and we must not leak
	// header mutations back to the caller's request object.
	r := req.Clone(req.Context())
	headers.Apply(r.Header, t.headers)
	return t.base.RoundTrip(r)
}

func newHeaderInjectingClient(headers map[string]string) *http.Client {
	return &http.Client{Transport: &headerInjectingTransport{
		headers: headers,
		base:    http.DefaultTransport,
	}}
}

// buildTokenSource constructs an oauth2.TokenSource for one grant from its
// resolved credential values. It performs no I/O: the token is exchanged
// lazily on the first Token() call. audience is only consulted by the
// jwt_bearer grant.
func buildTokenSource(ctx context.Context, grant string, vals map[string]string, scopes []string, cfgEndpoint, audience string) (oauth2.TokenSource, error) {
	switch grant {
	case grantRefreshToken:
		return refreshTokenTokenSource(ctx, vals, scopes, cfgEndpoint)
	case grantClientCredentials:
		return clientCredentialsTokenSource(ctx, vals, scopes, cfgEndpoint)
	case grantPassword:
		return passwordTokenSource(ctx, vals, scopes, cfgEndpoint)
	case grantJWTBearer:
		return jwtBearerTokenSource(ctx, vals, scopes, cfgEndpoint, audience)
	default:
		return nil, fmt.Errorf("unknown grant %q", grant)
	}
}

// jwtBearerTokenSource builds a token source for the RFC 7523 JWT-bearer grant.
// The proxy mints a JWT signed with an RSA private key (PEM bytes from the
// secret source) and POSTs it as the OAuth2 assertion. Covers DocuSign,
// Salesforce, Box, Zoom Server-to-Server, etc. — the audience and token
// endpoint distinguish providers.
func jwtBearerTokenSource(ctx context.Context, vals map[string]string, scopes []string, cfgEndpoint, audience string) (oauth2.TokenSource, error) {
	issuer := vals[fieldIssuer]
	subject := vals[fieldSubject]
	privateKey := vals[fieldPrivateKey]
	privateKeyID := vals[fieldPrivateKeyID] // optional
	if issuer == "" {
		return nil, fmt.Errorf("jwt_bearer grant is missing the issuer")
	}
	if subject == "" {
		return nil, fmt.Errorf("jwt_bearer grant is missing the subject")
	}
	if privateKey == "" {
		return nil, fmt.Errorf("jwt_bearer grant is missing the private key")
	}
	if cfgEndpoint == "" {
		return nil, fmt.Errorf("jwt_bearer grant needs a token endpoint: set \"token_endpoint\"")
	}
	if audience == "" {
		return nil, fmt.Errorf("jwt_bearer grant needs an audience: set \"audience\"")
	}

	cfg := &jwt.Config{
		Email:        issuer,
		Subject:      subject,
		PrivateKey:   []byte(privateKey),
		PrivateKeyID: privateKeyID,
		Audience:     audience,
		Scopes:       scopes,
		TokenURL:     cfgEndpoint,
	}
	return cfg.TokenSource(ctx), nil
}

// refreshTokenTokenSource builds a token source for the RFC 6749 refresh_token
// grant from discrete sources: a refresh token, a client id, and an optional
// client secret (public clients have none). The token endpoint comes from the
// configured token_endpoint.
func refreshTokenTokenSource(ctx context.Context, vals map[string]string, scopes []string, cfgEndpoint string) (oauth2.TokenSource, error) {
	refreshToken := vals[fieldRefreshToken]
	clientID := vals[fieldClientID]
	clientSecret := vals[fieldClientSecret] // empty for public clients
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh_token grant is missing the refresh token")
	}
	if clientID == "" {
		return nil, fmt.Errorf("refresh_token grant is missing the client id")
	}
	if cfgEndpoint == "" {
		return nil, fmt.Errorf("refresh_token grant needs a token endpoint: set \"token_endpoint\"")
	}

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			TokenURL: cfgEndpoint,
			// Send client_id/client_secret in the form body, never as HTTP
			// Basic. Every provider in scope accepts body auth.
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	// No access-token seed: the source exchanges the refresh token on first
	// use. One extra exchange at startup is cheaper than carrying a
	// provider-specific expiry format.
	return cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}), nil
}

// passwordTokenSource builds a token source for the RFC 6749 4.3 password
// (resource owner password credentials) grant. When the token endpoint returns
// a refresh_token the standard oauth2.Config token source uses it; otherwise
// the source re-runs the password exchange to refresh.
func passwordTokenSource(ctx context.Context, vals map[string]string, scopes []string, cfgEndpoint string) (oauth2.TokenSource, error) {
	username := vals[fieldUsername]
	password := vals[fieldPassword]
	clientID := vals[fieldClientID]
	clientSecret := vals[fieldClientSecret] // optional
	if username == "" || password == "" {
		return nil, fmt.Errorf("password grant is missing the username or password")
	}
	if clientID == "" {
		return nil, fmt.Errorf("password grant is missing the client id")
	}
	if cfgEndpoint == "" {
		return nil, fmt.Errorf("password grant needs a token endpoint: set \"token_endpoint\"")
	}

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			TokenURL:  cfgEndpoint,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	src := &passwordSource{ctx: ctx, cfg: cfg, username: username, password: password}
	return oauth2.ReuseTokenSource(nil, src), nil
}

// passwordSource implements oauth2.TokenSource by re-running the password
// exchange whenever a fresh token is requested. ReuseTokenSource wraps it to
// cache and single-flight, so this only fires on first use and after expiry.
type passwordSource struct {
	ctx                context.Context
	cfg                *oauth2.Config
	username, password string
}

func (s *passwordSource) Token() (*oauth2.Token, error) {
	return s.cfg.PasswordCredentialsToken(s.ctx, s.username, s.password)
}

// clientCredentialsTokenSource builds a token source for the RFC 6749 4.4
// client_credentials grant from discrete client_id and client_secret sources.
func clientCredentialsTokenSource(ctx context.Context, vals map[string]string, scopes []string, tokenURL string) (oauth2.TokenSource, error) {
	clientID := vals[fieldClientID]
	clientSecret := vals[fieldClientSecret]
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("client_credentials grant needs a client id and client secret")
	}
	cfg := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
		Scopes:       scopes,
		AuthStyle:    oauth2.AuthStyleInParams,
	}
	return cfg.TokenSource(ctx), nil
}

// logMintFailure classifies and logs a mint error and returns a short reason
// string for the audit annotation. An invalid_grant (revoked or expired
// refresh token) is unrecoverable and needs a human, so it logs at error
// level; everything else is potentially transient and logs at warn.
func (e *tokenEntry) logMintFailure(err error) string {
	reason, unrecoverable := classifyMintError(err)
	level := slog.LevelWarn
	if unrecoverable {
		level = slog.LevelError
	}
	if e.logger != nil {
		// err may carry the token endpoint's error response, which is the
		// standard OAuth2 error JSON and contains no credential material.
		e.logger.Log(context.Background(), level, "oauth_token mint failed",
			"grant", e.grant, "reason", reason, "error", err)
	}
	return reason
}

func classifyMintError(err error) (reason string, unrecoverable bool) {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		switch {
		case re.ErrorCode == "invalid_grant":
			return "invalid_grant", true
		case re.ErrorCode != "":
			return re.ErrorCode, false
		case re.Response != nil:
			return fmt.Sprintf("token_endpoint_http_%d", re.Response.StatusCode), false
		default:
			return "token_endpoint_error", false
		}
	}
	return "mint_failed", false
}
