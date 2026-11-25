package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/tenant"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// Source is a prepared secret. Get fetches the current value, possibly
// from a cache; Name returns a stable display name for logging.
type Source interface {
	Name() string
	Get(ctx context.Context) (string, error)
}

// secretSource is the package-internal alias for Source. Kept so existing
// internal call sites stay terse.
type secretSource = Source

// secretSourceBuilder validates source config and returns a secretSource that
// fetches lazily on first Get. Build must not perform I/O — only static
// config validation.
type secretSourceBuilder interface {
	Build(raw yaml.Node) (secretSource, error)
}

// sourceTypeHint is used to peek at the type field before dispatching to a builder.
type sourceTypeHint struct {
	Type string `yaml:"type"`
}

// sourceBuilderRegistry maps source type names to their builders.
type sourceBuilderRegistry map[string]secretSourceBuilder

const (
	defaultFailureTTL = time.Minute
	fetchTimeout      = 30 * time.Second
)

func parseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}

func newLazyValue(name string, successTTL, failureTTL time.Duration, logger *slog.Logger, fetch func(context.Context) (string, error)) *cachedValue {
	return &cachedValue{
		name:       name,
		logger:     logger,
		fetch:      fetch,
		successTTL: successTTL,
		failureTTL: failureTTL,
		now:        time.Now,
	}
}

// buildLazySource parses the TTL strings and returns a secretSource that
// lazily invokes fetch. successTTL of 0 (empty ttlStr) caches the value
// forever after first success. An empty failureTTLStr defaults to
// defaultFailureTTL.
func buildLazySource(name, ttlStr, failureTTLStr string, logger *slog.Logger, fetch func(context.Context) (string, error)) (secretSource, error) {
	successTTL, err := parseTTL(ttlStr)
	if err != nil {
		return nil, fmt.Errorf("parsing ttl %q: %w", ttlStr, err)
	}
	failureTTL, err := parseTTL(failureTTLStr)
	if err != nil {
		return nil, fmt.Errorf("parsing failure_ttl %q: %w", failureTTLStr, err)
	}
	if failureTTL == 0 {
		failureTTL = defaultFailureTTL
	}
	return newLazyValue(name, successTTL, failureTTL, logger, fetch), nil
}

// --- env builder ---

// envBuilder reads secrets from environment variables.
type envBuilder struct {
	getenv func(string) string
	logger *slog.Logger
}

type envConfig struct {
	Type string `yaml:"type"`
	Var  string `yaml:"var"`
}

func newEnvBuilder(logger *slog.Logger) *envBuilder {
	return &envBuilder{getenv: os.Getenv, logger: logger}
}

func (r *envBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg envConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing env source config: %w", err)
	}
	if cfg.Var == "" {
		return nil, fmt.Errorf("env source requires \"var\" field")
	}
	return buildLazySource(cfg.Var, "", "", r.logger, func(context.Context) (string, error) {
		v := r.getenv(cfg.Var)
		if v == "" {
			return "", fmt.Errorf("env var %q is not set or empty", cfg.Var)
		}
		return v, nil
	})
}

// --- file builder ---

// fileBuilder reads secrets from a file on disk. The file is re-read on every
// pipeline build (boot and each /v1/reload) and, when ttl is set, on cache
// expiry — so an integrator can rotate a running proxy's secret value by
// rewriting the file (atomically: write-temp + rename) and triggering a
// reload, without restarting the process. Unlike env (fixed at exec), a file
// is mutable for the process lifetime.
type fileBuilder struct {
	readFile func(string) ([]byte, error)
	logger   *slog.Logger
}

type fileConfig struct {
	Type       string `yaml:"type"`
	Path       string `yaml:"path"`
	TTL        string `yaml:"ttl,omitempty"`
	FailureTTL string `yaml:"failure_ttl,omitempty"`
}

func newFileBuilder(logger *slog.Logger) *fileBuilder {
	return &fileBuilder{readFile: os.ReadFile, logger: logger}
}

func (r *fileBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg fileConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing file source config: %w", err)
	}
	if cfg.Path == "" {
		return nil, fmt.Errorf("file source requires \"path\" field")
	}
	return buildLazySource(cfg.Path, cfg.TTL, cfg.FailureTTL, r.logger, func(context.Context) (string, error) {
		// The value is the exact file contents — no trimming. The writer
		// controls trailing whitespace, matching how Kubernetes and Docker
		// expose file-mounted secrets. Read each call so a ttl refresh sees
		// the current contents.
		b, err := r.readFile(cfg.Path)
		if err != nil {
			return "", fmt.Errorf("reading secret file %q: %w", cfg.Path, err)
		}
		if len(b) == 0 {
			return "", fmt.Errorf("secret file %q is empty", cfg.Path)
		}
		return string(b), nil
	})
}

// --- tenant_token source ---

// tenantTokenBuilder returns the verified tenant token carried by a request's
// context. It is only meaningful in tenancy mode; outside it, the source is
// unavailable. The token differs per request (and per tenant), so this source
// is deliberately not wrapped in the lazy/TTL cache.
type tenantTokenBuilder struct{}

type tenantTokenConfig struct {
	Type    string `yaml:"type"`
	JSONKey string `yaml:"json_key,omitempty"`
}

func newTenantTokenBuilder(_ *slog.Logger) *tenantTokenBuilder {
	return &tenantTokenBuilder{}
}

func (b *tenantTokenBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg tenantTokenConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing tenant_token source config: %w", err)
	}
	if cfg.JSONKey != "" {
		return nil, fmt.Errorf("tenant_token source does not support \"json_key\"")
	}
	return &tenantTokenSource{}, nil
}

type tenantTokenSource struct{}

func (s *tenantTokenSource) Name() string { return "tenant_token" }

func (s *tenantTokenSource) Get(ctx context.Context) (string, error) {
	tok, ok := tenant.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("tenant_token source requires a tenant token in the request context")
	}
	return tok.Raw, nil
}

// --- shared AWS client cache ---

// awsClientCache provides region-keyed caching for any AWS service client.
type awsClientCache[C any] struct {
	mu        sync.Mutex
	clients   map[string]C
	newClient func(cfg aws.Config) C
}

func (c *awsClientCache[C]) get(ctx context.Context, region string) (C, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.clients[region]; ok {
		return client, nil
	}
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	if dial := transform.OutboundDialer(); dial != nil {
		client := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
			tr.DialContext = dial
			// An env proxy would hide the real destination from the guard.
			tr.Proxy = nil
		})
		opts = append(opts, awsconfig.WithHTTPClient(client))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		var zero C
		return zero, fmt.Errorf("loading AWS config: %w", err)
	}
	client := c.newClient(cfg)
	c.clients[region] = client
	return client, nil
}

// --- AWS Secrets Manager builder ---

// smClient is the subset of the AWS Secrets Manager API used by awsSMBuilder.
type smClient interface {
	GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// awsSMBuilder reads secrets from AWS Secrets Manager.
type awsSMBuilder struct {
	clientFor func(ctx context.Context, region string) (smClient, error)
	logger    *slog.Logger
}

type awsSMConfig struct {
	Type       string `yaml:"type"`
	SecretID   string `yaml:"secret_id"`
	Region     string `yaml:"region,omitempty"`
	TTL        string `yaml:"ttl,omitempty"`
	FailureTTL string `yaml:"failure_ttl,omitempty"`
}

func newAWSSMBuilder(logger *slog.Logger) *awsSMBuilder {
	cache := &awsClientCache[smClient]{
		clients:   make(map[string]smClient),
		newClient: func(cfg aws.Config) smClient { return secretsmanager.NewFromConfig(cfg) },
	}
	return &awsSMBuilder{clientFor: cache.get, logger: logger}
}

func (r *awsSMBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg awsSMConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing aws_sm source config: %w", err)
	}
	if cfg.SecretID == "" {
		return nil, fmt.Errorf("aws_sm source requires \"secret_id\" field")
	}
	if cfg.Region != "" {
		if err := transform.ValidateAWSRegion(cfg.Region); err != nil {
			return nil, fmt.Errorf("aws_sm source: %w", err)
		}
	}
	return buildLazySource(cfg.SecretID, cfg.TTL, cfg.FailureTTL, r.logger, func(ctx context.Context) (string, error) {
		return r.fetchSecret(ctx, cfg)
	})
}

func (r *awsSMBuilder) fetchSecret(ctx context.Context, cfg awsSMConfig) (string, error) {
	client, err := r.clientFor(ctx, cfg.Region)
	if err != nil {
		return "", fmt.Errorf("creating AWS SM client: %w", err)
	}
	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(cfg.SecretID),
	})
	if err != nil {
		return "", fmt.Errorf("fetching secret %q: %w", cfg.SecretID, err)
	}
	val := aws.ToString(out.SecretString)
	if val == "" {
		return "", fmt.Errorf("secret %q resolved to empty value", cfg.SecretID)
	}
	return val, nil
}

// --- AWS Systems Manager Parameter Store builder ---

// ssmClient is the subset of the AWS SSM API used by awsSSMBuilder.
type ssmClient interface {
	GetParameter(ctx context.Context, input *ssm.GetParameterInput, opts ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// awsSSMBuilder reads secrets from AWS Systems Manager Parameter Store.
type awsSSMBuilder struct {
	clientFor func(ctx context.Context, region string) (ssmClient, error)
	logger    *slog.Logger
}

type awsSSMConfig struct {
	Type           string `yaml:"type"`
	Name           string `yaml:"name"`
	Region         string `yaml:"region,omitempty"`
	WithDecryption *bool  `yaml:"with_decryption,omitempty"`
	TTL            string `yaml:"ttl,omitempty"`
	FailureTTL     string `yaml:"failure_ttl,omitempty"`
}

func (cfg awsSSMConfig) decryptValue() bool {
	return cfg.WithDecryption == nil || *cfg.WithDecryption
}

func newAWSSSMBuilder(logger *slog.Logger) *awsSSMBuilder {
	cache := &awsClientCache[ssmClient]{
		clients:   make(map[string]ssmClient),
		newClient: func(cfg aws.Config) ssmClient { return ssm.NewFromConfig(cfg) },
	}
	return &awsSSMBuilder{clientFor: cache.get, logger: logger}
}

func (r *awsSSMBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg awsSSMConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing aws_ssm source config: %w", err)
	}
	if cfg.Name == "" {
		return nil, fmt.Errorf("aws_ssm source requires \"name\" field")
	}
	if cfg.Region != "" {
		if err := transform.ValidateAWSRegion(cfg.Region); err != nil {
			return nil, fmt.Errorf("aws_ssm source: %w", err)
		}
	}
	return buildLazySource(cfg.Name, cfg.TTL, cfg.FailureTTL, r.logger, func(ctx context.Context) (string, error) {
		return r.fetchParameter(ctx, cfg)
	})
}

func (r *awsSSMBuilder) fetchParameter(ctx context.Context, cfg awsSSMConfig) (string, error) {
	client, err := r.clientFor(ctx, cfg.Region)
	if err != nil {
		return "", fmt.Errorf("creating AWS SSM client: %w", err)
	}
	out, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(cfg.Name),
		WithDecryption: aws.Bool(cfg.decryptValue()),
	})
	if err != nil {
		return "", fmt.Errorf("fetching parameter %q: %w", cfg.Name, err)
	}
	if out == nil || out.Parameter == nil {
		return "", fmt.Errorf("parameter %q resolved without a value", cfg.Name)
	}
	val := aws.ToString(out.Parameter.Value)
	if val == "" {
		return "", fmt.Errorf("parameter %q resolved to empty value", cfg.Name)
	}
	return val, nil
}

// --- cached value (lazy fetch + TTL refresh + initial-failure caching) ---

// cachedValue wraps a fetch function with TTL-based caching. The first get()
// triggers the fetch. On success, the value is cached for successTTL (forever
// if successTTL is 0). On failure before any successful fetch, the error is
// cached for failureTTL so a struggling backend isn't hammered. After a
// successful fetch, later refresh failures serve the stale value.
type cachedValue struct {
	mu         sync.Mutex
	name       string
	logger     *slog.Logger
	fetch      func(ctx context.Context) (string, error)
	successTTL time.Duration
	failureTTL time.Duration
	now        func() time.Time

	initialized bool
	value       string
	lastErr     error
	expiresAt   time.Time
}

func (cv *cachedValue) Name() string { return cv.name }

func (cv *cachedValue) Get(ctx context.Context) (string, error) {
	cv.mu.Lock()
	defer cv.mu.Unlock()

	if cv.initialized {
		if cv.successTTL == 0 || cv.now().Before(cv.expiresAt) {
			return cv.value, nil
		}
	} else if cv.now().Before(cv.expiresAt) {
		return "", cv.lastErr
	}

	// Detach from the caller's context so a single client cancellation can't
	// poison the failure cache for unrelated requests.
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
	defer cancel()
	val, err := cv.fetch(fetchCtx)
	if err != nil {
		if cv.initialized {
			cv.expiresAt = cv.now().Add(cv.successTTL / 2)
			if cv.logger != nil {
				cv.logger.Warn("failed to refresh secret, serving stale value",
					"secret", cv.name,
					"error", err,
				)
			}
			return cv.value, nil
		}
		cv.lastErr = err
		cv.expiresAt = cv.now().Add(cv.failureTTL)
		if cv.logger != nil {
			cv.logger.Warn("failed to fetch secret, caching error",
				"secret", cv.name,
				"error", err,
				"retry_in", cv.failureTTL,
			)
		}
		return "", err
	}
	cv.value = val
	cv.initialized = true
	cv.lastErr = nil
	if cv.successTTL > 0 {
		cv.expiresAt = cv.now().Add(cv.successTTL)
	}
	return cv.value, nil
}

// --- JSON extraction ---

// jsonKeySource wraps a source whose value is a JSON object, exposing the
// single top-level string field named by key. The wrapped source caches the
// fetch; the JSON is re-parsed on every Get, which is cheap for the small
// credential objects json_key targets. Available to every source type via the
// optional json_key field (see resolveSource).
type jsonKeySource struct {
	inner secretSource
	key   string
}

func (s *jsonKeySource) Name() string { return s.inner.Name() }

func (s *jsonKeySource) Get(ctx context.Context) (string, error) {
	raw, err := s.inner.Get(ctx)
	if err != nil {
		return "", err
	}
	val, err := extractJSONKey(raw, s.key)
	if err != nil {
		return "", fmt.Errorf("extracting json_key %q from secret %q: %w", s.key, s.inner.Name(), err)
	}
	return val, nil
}

// extractJSONKey parses raw as JSON and returns the string value at key.
func extractJSONKey(raw, key string) (string, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return "", fmt.Errorf("secret value is not valid JSON: %w", err)
	}
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in JSON", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("key %q is not a string (type %T)", key, v)
	}
	return s, nil
}
