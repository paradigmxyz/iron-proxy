package secrets

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	turnkey "github.com/tkhq/go-sdk/v2"
	"gopkg.in/yaml.v3"
)

const turnkeyAPIPrivateKeyEnv = "TURNKEY_API_PRIVATE_KEY"

type turnkeyClient interface {
	ExportSecret(ctx context.Context, organizationID, secretID string, signerKey ...*ecdsa.PublicKey) ([]byte, error)
}

type turnkeyBuilder struct {
	clientFor func(organizationID, apiKeyEnv string) (turnkeyClient, error)
	logger    *slog.Logger
}

type turnkeyConfig struct {
	Type             string `yaml:"type"`
	OrganizationID   string `yaml:"organization_id"`
	SecretID         string `yaml:"secret_id"`
	APIPrivateKeyEnv string `yaml:"api_private_key_env,omitempty"`
	TTL              string `yaml:"ttl,omitempty"`
	FailureTTL       string `yaml:"failure_ttl,omitempty"`
}

func newTurnkeyBuilder(logger *slog.Logger) *turnkeyBuilder {
	cache := &turnkeyClientCache{newClient: newTurnkeyClient}
	return &turnkeyBuilder{clientFor: cache.get, logger: logger}
}

func (b *turnkeyBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg turnkeyConfig
	var fields map[string]yaml.Node
	if err := raw.Decode(&fields); err != nil {
		return nil, errors.New("turnkey source must be a mapping")
	}
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"organization_id", &cfg.OrganizationID}, {"secret_id", &cfg.SecretID},
		{"api_private_key_env", &cfg.APIPrivateKeyEnv}, {"ttl", &cfg.TTL}, {"failure_ttl", &cfg.FailureTTL},
	} {
		if node, ok := fields[field.name]; ok {
			if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
				return nil, fmt.Errorf("turnkey source %s must be a string", field.name)
			}
			if err := node.Decode(field.value); err != nil {
				return nil, fmt.Errorf("invalid turnkey source %s", field.name)
			}
		}
	}
	if cfg.OrganizationID == "" {
		return nil, errors.New("turnkey source requires organization_id")
	}
	if cfg.SecretID == "" {
		return nil, errors.New("turnkey source requires secret_id")
	}
	for _, field := range []struct{ name, value string }{{"ttl", cfg.TTL}, {"failure_ttl", cfg.FailureTTL}} {
		if duration, err := parseTTL(field.value); err != nil || duration < 0 {
			return nil, fmt.Errorf("turnkey source %s must be a non-negative duration", field.name)
		}
	}
	if cfg.APIPrivateKeyEnv == "" {
		cfg.APIPrivateKeyEnv = turnkeyAPIPrivateKeyEnv
	}
	return buildLazySource("turnkey:"+cfg.OrganizationID+"/"+cfg.SecretID, cfg.TTL, cfg.FailureTTL, b.logger, func(ctx context.Context) (string, error) {
		client, err := b.clientFor(cfg.OrganizationID, cfg.APIPrivateKeyEnv)
		if err != nil {
			return "", errors.New("turnkey secret client initialization failed")
		}
		plaintext, err := client.ExportSecret(ctx, cfg.OrganizationID, cfg.SecretID)
		defer clear(plaintext)
		if err != nil {
			// SDK errors can contain upstream response details. Keep them out of
			// lazy-source logs and proxy responses, including approval failures.
			return "", sanitizeTurnkeyError(err)
		}
		if len(plaintext) == 0 {
			return "", errors.New("turnkey secret is empty")
		}
		return string(plaintext), nil
	})
}

func newTurnkeyClient(organizationID, apiKeyEnv string) (turnkeyClient, error) {
	return newTurnkeySDKClient(organizationID, apiKeyEnv, http.DefaultTransport)
}

// Internal dependency injection keeps test endpoints out of source configuration.
func newTurnkeySDKClient(organizationID, apiKeyEnv string, transport http.RoundTripper, options ...turnkey.OptionFunc) (turnkeyClient, error) {
	privateKey := os.Getenv(apiKeyEnv)
	if privateKey == "" {
		return nil, errors.New("turnkey API private key environment variable is not set or empty")
	}
	stamper, err := turnkey.NewAPIKeyStamper(privateKey)
	if err != nil {
		return nil, errors.New("invalid turnkey API private key")
	}
	options = append(options,
		turnkey.WithHTTPClient(&http.Client{
			Timeout:   25 * time.Second,
			Transport: turnkeyTransport{inner: transport},
		}),
		// Retry only the SDK HTTP attempt: it reuses the body, stamp and recipient key.
		turnkey.WithHTTPRetries(2),
		// The SDK logs raw transport errors before we can sanitize them.
		turnkey.WithLogger(log.New(io.Discard, "", 0)),
	)
	client, err := turnkey.NewClient(stamper, organizationID, options...)
	if err != nil {
		return nil, errors.New("cannot initialize turnkey API client")
	}
	return client, nil
}

// The pinned SDK reconstructs http.Client and drops CheckRedirect. Reject
// redirects before net/http can forward a signed request to another target.
type turnkeyTransport struct {
	inner http.RoundTripper
}

func (t turnkeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if err := resp.Body.Close(); err != nil {
			return nil, errors.New("cannot close turnkey redirect response")
		}
		// No Location means net/http cannot follow; the SDK treats this 3xx
		// as a non-retryable failure. Discard the untrusted body and headers.
		return &http.Response{StatusCode: resp.StatusCode, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	}
	return resp, nil
}

// Clients contain immutable signing configuration and are shared across sources.
// Failed initialization is not cached, allowing a corrected environment to recover.
type turnkeyClientCache struct {
	mu        sync.Mutex
	clients   map[[2]string]turnkeyClient
	newClient func(string, string) (turnkeyClient, error)
}

func (c *turnkeyClientCache) get(org, env string) (turnkeyClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := [2]string{org, env}
	if client, ok := c.clients[key]; ok {
		return client, nil
	}
	client, err := c.newClient(org, env)
	if err != nil {
		return nil, err
	}
	if c.clients == nil {
		c.clients = make(map[[2]string]turnkeyClient)
	}
	c.clients[key] = client
	return client, nil
}

// Never interpolate SDK messages, response bodies, or activity details.
func sanitizeTurnkeyError(err error) error {
	category := "export_failed"
	var approval *turnkey.ActivityRequiresApprovalError
	var failed *turnkey.ActivityFailedError
	var request *turnkey.RequestError
	var transport *url.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		category = "timeout"
	case errors.Is(err, context.Canceled):
		category = "canceled"
	case errors.As(err, &approval):
		category = "approval_required"
	case errors.As(err, &failed):
		category = "activity_failed"
	case errors.As(err, &request):
		switch {
		case request.StatusCode >= 300 && request.StatusCode < 400:
			category = "redirect_rejected"
		case request.StatusCode == 401:
			category = "authentication_failed"
		case request.StatusCode == 403:
			category = "permission_denied"
		case request.StatusCode == 404:
			category = "not_found"
		case request.StatusCode == 429:
			category = "rate_limited"
		case request.StatusCode >= 500 && request.StatusCode < 600:
			category = "service_unavailable"
		default:
			category = "request_failed"
		}
	case errors.As(err, &transport):
		if transport.Timeout() {
			category = "timeout"
		} else {
			category = "transport_failed"
		}
	}
	return fmt.Errorf("turnkey secret export failed (%s)", category)
}
