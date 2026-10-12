// Package gcpidtoken implements a transform that mints Google-signed OIDC
// ID tokens and injects them as Bearer headers on matching requests.
//
// This is intended for private Cloud Run, Cloud Run functions, IAP, API
// Gateway, and other Google-backed targets that authenticate with an ID token
// whose aud claim names the receiving service. Unlike gcp_auth, this transform
// is audience-based and does not use OAuth scopes.
//
// Credentials come from exactly one service-account JSON source:
//   - keyfile_path: a service account JSON keyfile loaded from disk.
//   - keyfile: a service account JSON keyfile loaded from any registered
//     secret source (env, aws_sm, aws_ssm, 1password, 1password_connect).
//
// Like all header-injecting transforms, this requires MITM mode; sni-only
// mode has no way to rewrite headers.
package gcpidtoken

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/gcpjwt"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

const (
	defaultHeader              = "Authorization"
	serverlessHeader           = "X-Serverless-Authorization"
	stubAudience               = "iron-proxy-stub-audience"
	stubIDTokenLifetimeSeconds = 3600
)

func init() {
	transform.Register("gcp_id_token", factory)
}

type config struct {
	KeyfilePath string                 `yaml:"keyfile_path,omitempty"`
	Keyfile     yaml.Node              `yaml:"keyfile,omitempty"`
	Audience    string                 `yaml:"audience"`
	Header      string                 `yaml:"header,omitempty"`
	Rules       []hostmatch.RuleConfig `yaml:"rules"`
}

// GCPIDToken is the transform.
type GCPIDToken struct {
	rules    []hostmatch.Rule
	audience string
	header   string
	tsLoader tokenSourceLoader
	logger   *slog.Logger

	mu          sync.Mutex
	tokenSource oauth2.TokenSource
	principal   string
}

// tokenSourceLoader returns a fresh token source for one transform instance,
// plus a best-effort principal identifier for audit annotations.
type tokenSourceLoader func(ctx context.Context) (oauth2.TokenSource, string, error)

// sourceBuilder is the signature of secrets.BuildSource. Pulled out so tests
// can inject a stub instead of constructing real source backends.
type sourceBuilder func(yaml.Node, *slog.Logger) (secrets.Source, error)

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing gcp_id_token config: %w", err)
	}
	return newFromConfig(c, logger, os.ReadFile, secrets.BuildSource)
}

func newFromConfig(c config, logger *slog.Logger, readFile func(string) ([]byte, error), buildSource sourceBuilder) (*GCPIDToken, error) {
	hasPath := c.KeyfilePath != ""
	hasNested := c.Keyfile.Kind != 0
	if hasPath == hasNested {
		return nil, fmt.Errorf("gcp_id_token: requires exactly one of \"keyfile_path\" or \"keyfile\"")
	}
	if c.Audience == "" {
		return nil, fmt.Errorf("gcp_id_token: \"audience\" is required")
	}
	rules, err := hostmatch.CompileRulesAllowRequireTLS(c.Rules, "gcp_id_token")
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("gcp_id_token: at least one entry in \"rules\" is required")
	}
	header, err := normalizeHeader(c.Header)
	if err != nil {
		return nil, err
	}

	var tsLoader tokenSourceLoader
	switch {
	case hasPath:
		path := c.KeyfilePath
		audience := c.Audience
		tsLoader = func(ctx context.Context) (oauth2.TokenSource, string, error) {
			data, err := readFile(path)
			if err != nil {
				return nil, "", fmt.Errorf("reading GCP service account keyfile %q: %w", path, err)
			}
			return tokenSourceFromKeyfile(ctx, data, audience)
		}
	case hasNested:
		nested, err := buildSource(c.Keyfile, logger)
		if err != nil {
			return nil, fmt.Errorf("gcp_id_token: building keyfile source: %w", err)
		}
		audience := c.Audience
		tsLoader = func(ctx context.Context) (oauth2.TokenSource, string, error) {
			v, err := nested.Get(ctx)
			if err != nil {
				return nil, "", fmt.Errorf("loading GCP service account keyfile from %q: %w", nested.Name(), err)
			}
			return tokenSourceFromKeyfile(ctx, []byte(v), audience)
		}
	}

	return &GCPIDToken{
		rules:    rules,
		audience: c.Audience,
		header:   header,
		tsLoader: tsLoader,
		logger:   logger,
	}, nil
}

func normalizeHeader(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "authorization":
		return defaultHeader, nil
	case "x-serverless-authorization":
		return serverlessHeader, nil
	default:
		return "", fmt.Errorf("gcp_id_token: \"header\" must be \"authorization\" or \"x-serverless-authorization\"")
	}
}

// tokenSourceFromKeyfile parses a service-account JSON keyfile and returns a
// token source that exchanges a signed JWT assertion for a Google-signed ID
// token whose aud claim is audience.
func tokenSourceFromKeyfile(ctx context.Context, keyJSON []byte, audience string) (oauth2.TokenSource, string, error) {
	cfg, err := google.JWTConfigFromJSON(keyJSON)
	if err != nil {
		return nil, "", fmt.Errorf("parsing GCP service account keyfile: %w", err)
	}
	cfg.PrivateClaims = map[string]any{"target_audience": audience}
	cfg.UseIDToken = true

	var meta struct {
		ClientEmail string `json:"client_email"`
	}
	email := ""
	if err := json.Unmarshal(keyJSON, &meta); err == nil {
		email = meta.ClientEmail
	}
	return cfg.TokenSource(ctx), email, nil
}

func (g *GCPIDToken) Name() string { return "gcp_id_token" }

func (g *GCPIDToken) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if audience, kind, ok := stubRequest(req); ok {
		tok, err := fakeIDToken(audience)
		if err != nil {
			return nil, err
		}
		tctx.Annotate("stubbed", kind)
		if audience != "" {
			tctx.Annotate("audience", audience)
		}
		return &transform.TransformResult{
			Action:   transform.ActionStub,
			Response: stubResponse(req, kind, tok),
		}, nil
	}

	if !hostmatch.MatchAnyRule(g.rules, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	tok, err := g.mintToken(ctx)
	if err != nil {
		reason := g.logMintFailure(err)
		tctx.Annotate("error", reason)
		tctx.Annotate("rejected", "token_unavailable")
		return &transform.TransformResult{Action: transform.ActionReject}, nil
	}

	req.Header.Set(g.header, "Bearer "+tok)
	if g.principal != "" {
		tctx.Annotate("service_account", g.principal)
	}
	tctx.Annotate("audience", g.audience)
	tctx.Annotate("injected", []string{"header:" + g.header})
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (g *GCPIDToken) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (g *GCPIDToken) mintToken(ctx context.Context) (string, error) {
	ts, err := g.loadTokenSource(ctx)
	if err != nil {
		return "", err
	}
	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("minting GCP ID token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("GCP ID token source returned empty token")
	}
	return tok.AccessToken, nil
}

func (g *GCPIDToken) loadTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.tokenSource != nil {
		return g.tokenSource, nil
	}
	ts, principal, err := g.tsLoader(ctx)
	if err != nil {
		return nil, err
	}
	g.tokenSource = ts
	g.principal = principal
	return g.tokenSource, nil
}

func (g *GCPIDToken) logMintFailure(err error) string {
	reason := classifyMintError(err)
	if g.logger != nil {
		g.logger.Warn("gcp_id_token mint failed", "reason", reason, "error", err)
	}
	return reason
}

func classifyMintError(err error) string {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		switch {
		case re.ErrorCode != "":
			return re.ErrorCode
		case re.Response != nil:
			return fmt.Sprintf("token_endpoint_http_%d", re.Response.StatusCode)
		default:
			return "token_endpoint_error"
		}
	}
	return "mint_failed"
}

func stubRequest(req *http.Request) (audience string, kind string, ok bool) {
	if audience, ok := metadataIdentityAudience(req); ok {
		return audience, "gcp_metadata_identity_endpoint", true
	}
	if audience, ok := jwtBearerIDTokenAudience(req); ok {
		return audience, "gcp_oauth2_id_token_endpoint", true
	}
	return "", "", false
}

func metadataIdentityAudience(req *http.Request) (string, bool) {
	host := hostmatch.StripPort(req.Host)
	if host != "metadata.google.internal" && host != "169.254.169.254" {
		return "", false
	}
	path := ""
	if req.URL != nil {
		path = req.URL.Path
	}
	if !strings.HasPrefix(path, "/computeMetadata/v1/instance/service-accounts/") || !strings.HasSuffix(path, "/identity") {
		return "", false
	}
	audience := ""
	if req.URL != nil {
		audience = req.URL.Query().Get("audience")
	}
	if audience == "" {
		return "", false
	}
	return audience, true
}

func jwtBearerIDTokenAudience(req *http.Request) (string, bool) {
	host := hostmatch.StripPort(req.Host)
	path := ""
	if req.URL != nil {
		path = req.URL.Path
	}
	if host != "oauth2.googleapis.com" || path != "/token" {
		return "", false
	}
	return gcpjwt.JWTBearerTargetAudience(req)
}

func fakeIDToken(audience string) (string, error) {
	if audience == "" {
		audience = stubAudience
	}
	now := time.Now()
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
	}
	claims := map[string]any{
		"iss":            "https://accounts.google.com",
		"aud":            audience,
		"azp":            "iron-proxy-stub",
		"sub":            "iron-proxy-stub",
		"email":          "stub@iron-proxy.local",
		"email_verified": true,
		"iat":            now.Unix(),
		"exp":            now.Add(stubIDTokenLifetimeSeconds * time.Second).Unix(),
	}
	h, err := encodeJWTPart(header)
	if err != nil {
		return "", err
	}
	c, err := encodeJWTPart(claims)
	if err != nil {
		return "", err
	}
	sig := base64.RawURLEncoding.EncodeToString([]byte("stub-signature"))
	return h + "." + c + "." + sig, nil
}

func encodeJWTPart(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encoding stub ID token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func stubResponse(req *http.Request, kind, token string) *http.Response {
	if kind == "gcp_metadata_identity_endpoint" {
		body := []byte(token)
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"Content-Type": {"text/plain"}},
			Body:          transform.NewBufferedBodyFromBytes(body),
			ContentLength: int64(len(body)),
			Request:       req,
		}
	}
	body := []byte(`{"id_token":"` + token + `","expires_in":3600,"token_type":"Bearer"}`)
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          transform.NewBufferedBodyFromBytes(body),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
