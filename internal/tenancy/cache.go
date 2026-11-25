package tenancy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ironsh/iron-proxy/internal/tenant"
	"github.com/ironsh/iron-proxy/internal/transform"
)

const (
	// negativeFor is how long a failed fetch is remembered when there is no
	// config to fall back on, so a failing control plane is not hammered.
	negativeFor = 5 * time.Second
	// idleFor evicts tokens and pipelines with no traffic.
	idleFor = 15 * time.Minute
	// pruneEvery bounds how often the idle sweep runs.
	pruneEvery = time.Minute
	// maxTokens caps the number of cached tokens.
	maxTokens = 10000
	// maxConfigBytes bounds a control-plane response.
	maxConfigBytes = 16 << 20
)

// ControlPlaneTokenEnv names the environment variable holding the proxy's
// own credential for the control plane's tenant config endpoint. A tenant
// token alone never fetches a config: the endpoint requires this proxy
// credential, and the tenant token only selects whose config is returned.
const ControlPlaneTokenEnv = "IRON_TENANCY_CONTROL_PLANE_TOKEN"

// Builder builds a tenant's pipeline from the rules, secrets and transforms
// the control plane returned.
type Builder func(rules, secrets, transforms json.RawMessage) (*transform.Pipeline, error)

// Options configures a Cache.
type Options struct {
	Verifier *Verifier
	URL      string
	// ControlPlaneToken authenticates the proxy to the control plane.
	ControlPlaneToken string
	HTTPClient        *http.Client
	FreshFor          time.Duration
	StaleFor          time.Duration
	Build             Builder
	Logger            *slog.Logger
}

// Cache maps tenant tokens to the pipelines built from their configs.
//
// Configs are cached per token: a token's first CONNECT fetches its config,
// later ones reuse it, and once it is older than FreshFor the next request
// refreshes it (conditionally, by config_hash) while concurrent requests keep
// using the current pipeline. Pipelines are cached per config_hash, so every
// token served the same config shares one pipeline.
type Cache struct {
	opts Options
	now  func() time.Time

	mu        sync.Mutex
	tokens    map[string]*tokenEntry
	pipelines map[string]*pipelineEntry
	prunedAt  time.Time
}

type tokenEntry struct {
	// fetch serializes fetches for this token.
	fetch sync.Mutex

	// The fields below are guarded by Cache.mu.
	token *tenant.Token
	// hash is the control plane's config_hash, sent back on refresh so it can
	// answer "unchanged".
	hash string
	// key is the pipeline's key: a digest the proxy computed over the config
	// itself, so a control plane that reuses hashes can never hand one
	// tenant another tenant's pipeline.
	key       string
	fetchedAt time.Time
	lastUsed  time.Time
	failure   *Rejection
	failedAt  time.Time
}

type pipelineEntry struct {
	pipeline *transform.Pipeline
	lastUsed time.Time
}

// New returns a Cache.
func New(opts Options) *Cache {
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Cache{
		opts:      opts,
		now:       time.Now,
		tokens:    make(map[string]*tokenEntry),
		pipelines: make(map[string]*pipelineEntry),
	}
}

// Rejection is why a request could not be bound to a tenant. Message is safe
// to send to the client; it never contains the token.
type Rejection struct {
	Status int
	Code   string
	// Challenge asks for credentials (407 with Proxy-Authenticate).
	Challenge bool
}

func (r *Rejection) Error() string { return r.Code }

var (
	rejectTokenRequired = &Rejection{Status: http.StatusProxyAuthRequired, Code: "tenant_token_required", Challenge: true}
	rejectTokenInvalid  = &Rejection{Status: http.StatusProxyAuthRequired, Code: "tenant_token_invalid", Challenge: true}
	rejectTenant        = &Rejection{Status: http.StatusForbidden, Code: "tenant_refused"}
	rejectUnavailable   = &Rejection{Status: http.StatusServiceUnavailable, Code: "tenant_config_unavailable"}
	rejectTokenExpired  = &Rejection{Status: http.StatusUnauthorized, Code: "tenant_token_expired"}
)

// Bind authenticates a Proxy-Authorization value and returns the tenant it
// belongs to, with the pipeline to run its requests through.
func (c *Cache) Bind(ctx context.Context, proxyAuthorization string) (*transform.Tenant, *Rejection) {
	raw, ok := BearerToken(proxyAuthorization)
	if !ok {
		return nil, rejectTokenRequired
	}
	tok, err := c.opts.Verifier.Verify(raw)
	if err != nil {
		c.opts.Logger.Debug("tenant token refused", slog.String("reason", err.Error()))
		return nil, rejectTokenInvalid
	}
	return c.Resolve(ctx, tok)
}

// Resolve returns the current pipeline for an already verified token. The
// proxy calls it for every request inside a tunnel, so refreshes, control
// plane refusals and invalidations take effect on the tunnel's next request.
func (c *Cache) Resolve(ctx context.Context, tok *tenant.Token) (*transform.Tenant, *Rejection) {
	if tok.Expired(c.now()) {
		return nil, rejectTokenExpired
	}
	// A client that disconnects must not fail the fetch for every other
	// user of the token; the HTTP client's timeout bounds it.
	ctx = context.WithoutCancel(ctx)
	key := tokenKey(tok.Raw)
	entry := c.entry(key, tok)

	if pl, fresh := c.current(entry); pl != nil && fresh {
		return &transform.Tenant{Token: tok, Pipeline: pl}, nil
	}
	// Another request is already refreshing this token: keep using the
	// current pipeline instead of queueing behind it.
	if !entry.fetch.TryLock() {
		if pl, _ := c.current(entry); pl != nil && c.usable(entry) {
			return &transform.Tenant{Token: tok, Pipeline: pl}, nil
		}
		entry.fetch.Lock()
	}
	defer entry.fetch.Unlock()

	// It may have been refreshed while this request waited.
	if pl, fresh := c.current(entry); pl != nil && fresh {
		return &transform.Tenant{Token: tok, Pipeline: pl}, nil
	}
	if rej := c.recentFailure(entry); rej != nil {
		return nil, rej
	}
	pl, rej := c.refresh(ctx, key, entry)
	if rej != nil {
		return nil, rej
	}
	return &transform.Tenant{Token: tok, Pipeline: pl}, nil
}

// configDigest is the proxy's key for a config: a digest of exactly what the
// pipeline is built from.
func configDigest(rules, secrets, transforms json.RawMessage) string {
	h := sha256.New()
	for _, part := range [][]byte{rules, secrets, transforms} {
		_, _ = fmt.Fprintf(h, "%d:", len(part)) // hash writes never fail
		_, _ = h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func tokenKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (c *Cache) entry(key string, tok *tenant.Token) *tokenEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.pruneLocked(now)
	entry, ok := c.tokens[key]
	if !ok {
		if len(c.tokens) >= maxTokens {
			c.evictOldestLocked()
		}
		entry = &tokenEntry{token: tok}
		c.tokens[key] = entry
	}
	entry.lastUsed = now
	return entry
}

// current returns the entry's pipeline and whether it is fresh.
func (c *Cache) current(entry *tokenEntry) (*transform.Pipeline, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry.key == "" {
		return nil, false
	}
	pe, ok := c.pipelines[entry.key]
	if !ok {
		return nil, false
	}
	now := c.now()
	pe.lastUsed = now
	return pe.pipeline, now.Sub(entry.fetchedAt) < c.opts.FreshFor
}

// usable reports whether the entry's config is still within StaleFor.
func (c *Cache) usable(entry *tokenEntry) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return entry.key != "" && c.now().Sub(entry.fetchedAt) < c.opts.StaleFor
}

// recentFailure is the last failure when it is recent and there is no usable
// config to serve instead (none yet, or one older than StaleFor).
func (c *Cache) recentFailure(entry *tokenEntry) *Rejection {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	usable := entry.key != "" && now.Sub(entry.fetchedAt) < c.opts.StaleFor
	if entry.failure != nil && !usable && now.Sub(entry.failedAt) < negativeFor {
		return entry.failure
	}
	return nil
}

// refresh fetches the token's config and returns the pipeline to use. Called
// with entry.fetch held.
func (c *Cache) refresh(ctx context.Context, key string, entry *tokenEntry) (*transform.Pipeline, *Rejection) {
	c.mu.Lock()
	known, knownKey := entry.hash, entry.key
	if _, ok := c.pipelines[knownKey]; !ok {
		known, knownKey = "", ""
	}
	c.mu.Unlock()

	resp, err := c.fetchConfig(ctx, entry.token.Raw, known)
	if err != nil {
		var rej *Rejection
		if errors.As(err, &rej) {
			// The control plane refused this token or tenant: never serve
			// its cached config again, and remember the refusal briefly so
			// a revoked token does not reach the control plane every time.
			c.mu.Lock()
			entry.hash, entry.key = "", ""
			entry.failure = rej
			entry.failedAt = c.now()
			c.mu.Unlock()
			return nil, rej
		}
		c.opts.Logger.Warn("tenant config fetch failed", slog.String("error", err.Error()))
		if pl, _ := c.current(entry); pl != nil && c.usable(entry) {
			return pl, nil
		}
		c.mu.Lock()
		entry.failure = rejectUnavailable
		entry.failedAt = c.now()
		c.mu.Unlock()
		return nil, rejectUnavailable
	}

	pipelineKey := knownKey
	if resp.full {
		pipelineKey = resp.digest
	}
	pl, err := c.pipelineFor(pipelineKey, resp)
	if err != nil {
		// Build errors can quote config values (YAML decode errors do), and
		// tenant configs carry secrets: never log the error itself.
		c.opts.Logger.Error("building tenant pipeline failed", slog.String("config_hash", resp.ConfigHash))
		if pl, _ := c.current(entry); pl != nil && c.usable(entry) {
			return pl, nil
		}
		c.mu.Lock()
		entry.failure = rejectUnavailable
		entry.failedAt = c.now()
		c.mu.Unlock()
		return nil, rejectUnavailable
	}
	c.mu.Lock()
	entry.hash = resp.ConfigHash
	entry.key = pipelineKey
	entry.fetchedAt = c.now()
	entry.failure = nil
	c.mu.Unlock()
	return pl, nil
}

// pipelineFor returns the pipeline under key, building it from resp only
// when no token has been served that exact config yet.
func (c *Cache) pipelineFor(key string, resp *configResponse) (*transform.Pipeline, error) {
	c.mu.Lock()
	if pe, ok := c.pipelines[key]; ok {
		pe.lastUsed = c.now()
		c.mu.Unlock()
		return pe.pipeline, nil
	}
	c.mu.Unlock()
	if !resp.full {
		return nil, errors.New("control plane returned only a hash for an unknown config")
	}
	pl, err := c.opts.Build(resp.Rules, resp.Secrets, resp.Transforms)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// A concurrent fetch for another token may have built it meanwhile; the
	// duplicate was never used, so close it now.
	if pe, ok := c.pipelines[key]; ok {
		closePipeline(pl, c.opts.Logger)
		return pe.pipeline, nil
	}
	c.pipelines[key] = &pipelineEntry{pipeline: pl, lastUsed: c.now()}
	return pl, nil
}

func closePipeline(pl *transform.Pipeline, logger *slog.Logger) {
	if err := pl.Close(); err != nil {
		logger.Warn("closing tenant pipeline", slog.String("error", err.Error()))
	}
}

// TenantTokenHeader carries the tenant token on a config request. The body
// is the same as a managed proxy's sync request.
const TenantTokenHeader = "X-Iron-Tenant-Token"

type configRequest struct {
	ConfigHash string `json:"config_hash"`
}

type configResponse struct {
	ConfigHash string          `json:"config_hash"`
	Rules      json.RawMessage `json:"rules"`
	Secrets    json.RawMessage `json:"secrets"`
	Transforms json.RawMessage `json:"transforms"`
	// full is whether the response carried the config, not just its hash.
	full bool
	// digest is the proxy's own key for a full config.
	digest string
}

// fetchConfig asks the control plane for the token's config, authenticated
// as the proxy; the tenant token only selects the tenant. A known hash lets
// it answer with only the hash when nothing changed. A tenant refusal comes
// back as *Rejection; anything else (including the control plane refusing
// the proxy itself) is an availability error.
func (c *Cache) fetchConfig(ctx context.Context, raw, knownHash string) (*configResponse, error) {
	body, err := json.Marshal(configRequest{ConfigHash: knownHash})
	if err != nil {
		return nil, fmt.Errorf("encoding config request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opts.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building config request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.opts.ControlPlaneToken)
	req.Header.Set(TenantTokenHeader, raw)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting tenant config: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading tenant config: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, errors.New("the control plane refused the proxy's credential")
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
		return nil, rejectTenant
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("tenant config request failed with status %d", resp.StatusCode)
	case len(data) > maxConfigBytes:
		return nil, fmt.Errorf("tenant config exceeds %d bytes", maxConfigBytes)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, errors.New("tenant config is not a JSON object")
	}
	var out configResponse
	if err := json.Unmarshal(data, &out); err != nil || out.ConfigHash == "" {
		return nil, errors.New("tenant config has no config_hash")
	}
	_, hasRules := fields["rules"]
	_, hasSecrets := fields["secrets"]
	_, hasTransforms := fields["transforms"]
	out.full = hasRules || hasSecrets || hasTransforms
	if !out.full && (knownHash == "" || out.ConfigHash != knownHash) {
		return nil, errors.New("control plane returned only a hash for a config this token was never served")
	}
	if out.full {
		out.digest = configDigest(out.Rules, out.Secrets, out.Transforms)
	}
	return &out, nil
}

// pruneLocked drops idle tokens and pipelines no token uses. Runs at most
// once per pruneEvery. Called with c.mu held.
func (c *Cache) pruneLocked(now time.Time) {
	if now.Sub(c.prunedAt) < pruneEvery {
		return
	}
	c.prunedAt = now
	live := make(map[string]bool)
	for key, entry := range c.tokens {
		if now.Sub(entry.lastUsed) >= idleFor || entry.token.Expired(now) {
			delete(c.tokens, key)
			continue
		}
		live[entry.key] = true
	}
	for key, pe := range c.pipelines {
		// Unused for idleFor, so no request is still running through it.
		if !live[key] && now.Sub(pe.lastUsed) >= idleFor {
			delete(c.pipelines, key)
			closePipeline(pe.pipeline, c.opts.Logger)
		}
	}
}

func (c *Cache) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for key, entry := range c.tokens {
		if oldestKey == "" || entry.lastUsed.Before(oldest) {
			oldestKey, oldest = key, entry.lastUsed
		}
	}
	delete(c.tokens, oldestKey)
}
