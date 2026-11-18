// Package oauth implements a transform that mints OAuth2 access tokens and
// injects them as Authorization: Bearer headers on matching requests.
//
// One oauth_token transform carries a list of token entries. Each entry names
// an OAuth2 grant (refresh_token, client_credentials, password, or
// jwt_bearer), the credential fields it needs — each resolved from any
// secrets-package source (env, 1password, 1password_connect, aws_sm, aws_ssm)
// — and host rules selecting the requests it applies to. Token exchange,
// caching, refresh, and single-flight are delegated to golang.org/x/oauth2 —
// the same code path the official SDKs use.
//
// Entries may also declare token_endpoint_headers: a map of header name to
// secret source whose resolved values are sent on the token POST itself. Some
// vendors require an api-key header on the token endpoint in addition to the
// standard client_id / client_secret form fields.
//
// The jwt_bearer grant (RFC 7523) covers vendors that authenticate with a
// signed JWT assertion — DocuSign, Salesforce, Box, Zoom Server-to-Server,
// etc. GCP service-account auth uses the same flow but has a vendor-specific
// keyfile format and is handled by the separate gcp_auth transform.
//
// Like all header-injecting transforms, this requires MITM mode; sni-only
// mode has no way to rewrite headers.
package oauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

const (
	grantRefreshToken      = "refresh_token"
	grantClientCredentials = "client_credentials"
	grantPassword          = "password"
	grantJWTBearer         = "jwt_bearer"
)

// Credential field keys. They name both a config field and the corresponding
// key in the resolved-value map handed to the token-source builders, so the
// two sides stay in sync.
const (
	fieldRefreshToken = "refresh_token"
	fieldClientID     = "client_id"
	fieldClientSecret = "client_secret"
	fieldUsername     = "username"
	fieldPassword     = "password"
	fieldIssuer       = "issuer"
	fieldSubject      = "subject"
	fieldPrivateKey   = "private_key"
	fieldPrivateKeyID = "private_key_id"
)

// stubAccessToken is the placeholder bearer returned to clients that fetch a
// token from a configured token endpoint through the proxy. The real token is
// minted by oauth_token and swapped in just before the request leaves the
// proxy, so the value here never reaches the upstream: it only has to look
// like an opaque token to the client SDK.
const stubAccessToken = "iron-proxy-stub-token"

var stubTokenJSON = []byte(`{"access_token":"` + stubAccessToken + `","expires_in":3600,"token_type":"Bearer"}`)

func init() {
	transform.Register("oauth_token", factory)
}

type config struct {
	Tokens []tokenEntryConfig `yaml:"tokens"`
}

type tokenEntryConfig struct {
	Grant string `yaml:"grant"`

	// Credential fields. Each is a secrets source resolved independently, so
	// the fields can live in different stores or be pulled out of one JSON
	// secret with json_key. ClientSecret is optional for public refresh_token
	// clients. Username and Password are only used by the password grant.
	// Issuer/Subject/PrivateKey/PrivateKeyID are only used by the jwt_bearer
	// grant.
	RefreshToken yaml.Node `yaml:"refresh_token"`
	ClientID     yaml.Node `yaml:"client_id"`
	ClientSecret yaml.Node `yaml:"client_secret"`
	Username     yaml.Node `yaml:"username"`
	Password     yaml.Node `yaml:"password"`
	Issuer       yaml.Node `yaml:"issuer"`
	Subject      yaml.Node `yaml:"subject"`
	PrivateKey   yaml.Node `yaml:"private_key"`
	PrivateKeyID yaml.Node `yaml:"private_key_id"`

	// Audience is the JWT "aud" claim for the jwt_bearer grant. It is a plain
	// string because it is a per-provider constant (e.g. "account.docusign.com",
	// "https://login.salesforce.com") and never rotated.
	Audience string `yaml:"audience,omitempty"`

	TokenEndpoint string                 `yaml:"token_endpoint,omitempty"`
	Scopes        []string               `yaml:"scopes,omitempty"`
	Rules         []hostmatch.RuleConfig `yaml:"rules"`
	Header        string                 `yaml:"header,omitempty"`
	ValuePrefix   string                 `yaml:"value_prefix,omitempty"`

	// Require rejects the request with a 502 when the token cannot be minted.
	// When false (default), a mint failure is logged and the request is
	// forwarded without the token so one broken credential doesn't take down
	// every request the entry matches. Mirrors the secrets transform's
	// "require" flag.
	Require bool `yaml:"require,omitempty"`

	// TokenEndpointHeaders is a map of header name to secret source. Each
	// resolved value is sent as a request header on the token POST itself —
	// used by vendors that require an api-key header alongside the standard
	// form-body client auth.
	TokenEndpointHeaders map[string]yaml.Node `yaml:"token_endpoint_headers,omitempty"`
}

// sourceBuilder is the signature of secrets.BuildSource. Pulled out so tests
// can inject a stub instead of constructing real source backends.
type sourceBuilder func(yaml.Node, *slog.Logger) (secrets.Source, error)

// OAuth is the transform.
type OAuth struct {
	entries       []*tokenEntry
	stubEndpoints []tokenEndpoint
}

// tokenEntry is one resolved entry from config.tokens.
type tokenEntry struct {
	grant       string
	scopes      []string
	rules       []hostmatch.Rule
	header      string
	valuePrefix string
	cfgEndpoint string // config token_endpoint
	audience    string // JWT "aud" claim, jwt_bearer grant only
	require     bool   // reject the request when minting fails
	logger      *slog.Logger

	// sources holds the entry's credential secret sources, keyed by field.
	sources map[string]secrets.Source

	// endpointHeaderSources holds secret sources for headers sent on the
	// token POST itself, keyed by header name.
	endpointHeaderSources map[string]secrets.Source

	// mu guards the lazily built token source and the fingerprint of the
	// credential values it was built from. The token source is rebuilt when
	// any source value changes (e.g. a credential's ttl expired and the secret
	// store returned a new value). The fingerprint is a BLAKE3 digest of the
	// resolved values, so plaintext secrets aren't retained on the entry.
	mu          sync.Mutex
	fingerprint [32]byte
	tokenSource oauth2.TokenSource
}

// tokenEndpoint is a host+path pair that, when matched by an inbound request,
// is served a synthetic token response instead of being forwarded.
type tokenEndpoint struct {
	host string
	path string
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing oauth_token config: %w", err)
	}
	return newFromConfig(c, logger, secrets.BuildSource)
}

func newFromConfig(c config, logger *slog.Logger, buildSource sourceBuilder) (*OAuth, error) {
	if len(c.Tokens) == 0 {
		return nil, fmt.Errorf("oauth_token: at least one entry in \"tokens\" is required")
	}
	o := &OAuth{}
	for i, tc := range c.Tokens {
		entry, stub, err := buildEntry(tc, logger, buildSource)
		if err != nil {
			return nil, fmt.Errorf("oauth_token: tokens[%d]: %w", i, err)
		}
		o.entries = append(o.entries, entry)
		if stub != nil {
			o.stubEndpoints = append(o.stubEndpoints, *stub)
		}
	}
	return o, nil
}

// isSet reports whether a credential yaml.Node was present in config. An
// absent mapping field decodes to the zero Node, whose Kind is 0.
func isSet(n yaml.Node) bool { return n.Kind != 0 }

func buildEntry(tc tokenEntryConfig, logger *slog.Logger, buildSource sourceBuilder) (*tokenEntry, *tokenEndpoint, error) {
	switch tc.Grant {
	case grantRefreshToken, grantClientCredentials, grantPassword, grantJWTBearer:
	default:
		return nil, nil, fmt.Errorf("\"grant\" must be one of refresh_token, client_credentials, password, jwt_bearer (got %q)", tc.Grant)
	}
	if tc.TokenEndpoint == "" {
		return nil, nil, fmt.Errorf("%s grant requires \"token_endpoint\"", tc.Grant)
	}
	if tc.Grant == grantJWTBearer && tc.Audience == "" {
		return nil, nil, fmt.Errorf("jwt_bearer grant requires \"audience\"")
	}

	sources, err := buildCredentialSources(tc, logger, buildSource)
	if err != nil {
		return nil, nil, err
	}

	endpointHeaders, err := buildEndpointHeaderSources(tc.TokenEndpointHeaders, logger, buildSource)
	if err != nil {
		return nil, nil, err
	}

	rules, err := hostmatch.CompileRulesAllowRequireTLS(tc.Rules, "rules")
	if err != nil {
		return nil, nil, err
	}
	if len(rules) == 0 {
		return nil, nil, fmt.Errorf("at least one entry in \"rules\" is required")
	}

	var stub *tokenEndpoint
	if tc.TokenEndpoint != "" {
		stub, err = parseTokenEndpoint(tc.TokenEndpoint)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid token_endpoint: %w", err)
		}
	}

	header := tc.Header
	if header == "" {
		header = "Authorization"
	}
	valuePrefix := tc.ValuePrefix
	if valuePrefix == "" {
		valuePrefix = "Bearer "
	}

	return &tokenEntry{
		grant:                 tc.Grant,
		scopes:                tc.Scopes,
		rules:                 rules,
		header:                header,
		valuePrefix:           valuePrefix,
		cfgEndpoint:           tc.TokenEndpoint,
		audience:              tc.Audience,
		require:               tc.Require,
		sources:               sources,
		endpointHeaderSources: endpointHeaders,
		logger:                logger,
	}, stub, nil
}

// buildCredentialSources resolves an entry's credential secret sources, one
// per field.
func buildCredentialSources(tc tokenEntryConfig, logger *slog.Logger, buildSource sourceBuilder) (map[string]secrets.Source, error) {
	build := func(field string, n yaml.Node) (secrets.Source, error) {
		src, err := buildSource(n, logger)
		if err != nil {
			return nil, fmt.Errorf("building %s source: %w", field, err)
		}
		return src, nil
	}
	buildAll := func(fields map[string]yaml.Node) (map[string]secrets.Source, error) {
		sources := make(map[string]secrets.Source, len(fields))
		for field, node := range fields {
			src, err := build(field, node)
			if err != nil {
				return nil, err
			}
			sources[field] = src
		}
		return sources, nil
	}

	switch tc.Grant {
	case grantRefreshToken:
		if !isSet(tc.RefreshToken) {
			return nil, fmt.Errorf("refresh_token grant requires \"refresh_token\"")
		}
		if !isSet(tc.ClientID) {
			return nil, fmt.Errorf("refresh_token grant requires \"client_id\"")
		}
		fields := map[string]yaml.Node{
			fieldRefreshToken: tc.RefreshToken,
			fieldClientID:     tc.ClientID,
		}
		if isSet(tc.ClientSecret) {
			fields[fieldClientSecret] = tc.ClientSecret
		}
		return buildAll(fields)

	case grantClientCredentials:
		if !isSet(tc.ClientID) || !isSet(tc.ClientSecret) {
			return nil, fmt.Errorf("client_credentials grant requires \"client_id\" and \"client_secret\"")
		}
		return buildAll(map[string]yaml.Node{
			fieldClientID:     tc.ClientID,
			fieldClientSecret: tc.ClientSecret,
		})

	case grantPassword:
		if !isSet(tc.Username) || !isSet(tc.Password) {
			return nil, fmt.Errorf("password grant requires \"username\" and \"password\"")
		}
		if !isSet(tc.ClientID) {
			return nil, fmt.Errorf("password grant requires \"client_id\"")
		}
		fields := map[string]yaml.Node{
			fieldUsername: tc.Username,
			fieldPassword: tc.Password,
			fieldClientID: tc.ClientID,
		}
		if isSet(tc.ClientSecret) {
			fields[fieldClientSecret] = tc.ClientSecret
		}
		return buildAll(fields)

	case grantJWTBearer:
		if !isSet(tc.Issuer) {
			return nil, fmt.Errorf("jwt_bearer grant requires \"issuer\"")
		}
		if !isSet(tc.Subject) {
			return nil, fmt.Errorf("jwt_bearer grant requires \"subject\"")
		}
		if !isSet(tc.PrivateKey) {
			return nil, fmt.Errorf("jwt_bearer grant requires \"private_key\"")
		}
		fields := map[string]yaml.Node{
			fieldIssuer:     tc.Issuer,
			fieldSubject:    tc.Subject,
			fieldPrivateKey: tc.PrivateKey,
		}
		if isSet(tc.PrivateKeyID) {
			fields[fieldPrivateKeyID] = tc.PrivateKeyID
		}
		return buildAll(fields)
	}
	return nil, fmt.Errorf("unknown grant %q", tc.Grant) // unreachable: grant is validated above
}

// buildEndpointHeaderSources resolves each token_endpoint_headers entry to a
// secrets.Source. Header names are kept verbatim so vendors that demand a
// specific casing (e.g. "x-api-key") get it on the wire.
func buildEndpointHeaderSources(headers map[string]yaml.Node, logger *slog.Logger, buildSource sourceBuilder) (map[string]secrets.Source, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	out := make(map[string]secrets.Source, len(headers))
	for name, node := range headers {
		if name == "" {
			return nil, fmt.Errorf("token_endpoint_headers: header name must not be empty")
		}
		src, err := buildSource(node, logger)
		if err != nil {
			return nil, fmt.Errorf("token_endpoint_headers[%q]: %w", name, err)
		}
		out[name] = src
	}
	return out, nil
}

// parseTokenEndpoint splits a configured token endpoint URL into the host and
// path used to recognize a client's token request for stubbing.
func parseTokenEndpoint(raw string) (*tokenEndpoint, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%q has no host", raw)
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return &tokenEndpoint{host: hostmatch.StripPort(u.Host), path: path}, nil
}

func (o *OAuth) Name() string { return "oauth_token" }

func (o *OAuth) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	// Stubbing a configured token endpoint runs before host rules so a
	// sandboxed SDK can always complete its own token dance against the proxy
	// with a placeholder token. oauth_token mints the real token separately
	// and injects it on the API request.
	if o.matchesTokenEndpoint(req) {
		tctx.Annotate("stubbed", "oauth2_token_endpoint")
		return &transform.TransformResult{
			Action:   transform.ActionStub,
			Response: stubTokenResponse(req),
		}, nil
	}

	// First entry whose rules host-match wins; config order is the tie-breaker.
	entry := o.matchEntry(req)
	if entry == nil {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	tok, err := entry.mint(ctx)
	if err != nil {
		reason := entry.logMintFailure(err)
		tctx.Annotate("grant", entry.grant)
		tctx.Annotate("error", reason)
		if entry.require {
			tctx.Annotate("rejected", "token_unavailable")
			// Fail closed with a 502: forwarding an unauthenticated request
			// would surface as a confusing upstream 401.
			return &transform.TransformResult{
				Action:   transform.ActionReject,
				Response: mintFailureResponse(req, entry.grant),
			}, nil
		}
		// Fail open: forward the request without the token rather than taking
		// down every request this entry matches. The header is left untouched,
		// so the upstream sees the request as if no token were configured.
		tctx.Annotate("skipped", "token_unavailable")
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	req.Header.Set(entry.header, entry.valuePrefix+tok)
	tctx.Annotate("grant", entry.grant)
	tctx.Annotate("injected", []string{"header:" + http.CanonicalHeaderKey(entry.header)})
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (o *OAuth) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// matchEntry returns the first entry whose host rules match req, or nil.
func (o *OAuth) matchEntry(req *http.Request) *tokenEntry {
	for _, e := range o.entries {
		if hostmatch.MatchAnyRule(e.rules, req) {
			return e
		}
	}
	return nil
}

// matchesTokenEndpoint reports whether req targets one of the configured token
// endpoints, which the proxy serves with a synthetic token instead of
// forwarding.
func (o *OAuth) matchesTokenEndpoint(req *http.Request) bool {
	host := hostmatch.StripPort(req.Host)
	var path string
	if req.URL != nil {
		path = req.URL.Path
	}
	for _, te := range o.stubEndpoints {
		if te.host == host && te.path == path {
			return true
		}
	}
	return false
}

func stubTokenResponse(req *http.Request) *http.Response {
	return jsonResponse(req, http.StatusOK, "200 OK", stubTokenJSON)
}

func mintFailureResponse(req *http.Request, grant string) *http.Response {
	// grant is a config-validated enum, so it is safe to interpolate.
	body := []byte(`{"error":"oauth_token failed to mint an access token","grant":"` + grant + `"}`)
	return jsonResponse(req, http.StatusBadGateway, "502 Bad Gateway", body)
}

func jsonResponse(req *http.Request, status int, statusText string, body []byte) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        statusText,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          transform.NewBufferedBodyFromBytes(body),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
