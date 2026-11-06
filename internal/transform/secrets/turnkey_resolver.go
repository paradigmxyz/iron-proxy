package secrets

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
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
	return &turnkeyBuilder{clientFor: newTurnkeyClient, logger: logger}
}

func (b *turnkeyBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg turnkeyConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, errors.New("invalid turnkey source configuration")
	}
	if cfg.OrganizationID == "" || cfg.SecretID == "" {
		return nil, errors.New("turnkey source requires organization_id and secret_id")
	}
	if cfg.APIPrivateKeyEnv == "" {
		cfg.APIPrivateKeyEnv = turnkeyAPIPrivateKeyEnv
	}
	return buildLazySource("turnkey:"+cfg.OrganizationID+"/"+cfg.SecretID, cfg.TTL, cfg.FailureTTL, b.logger, func(ctx context.Context) (string, error) {
		client, err := b.clientFor(cfg.OrganizationID, cfg.APIPrivateKeyEnv)
		if err != nil {
			return "", errors.New("cannot initialize turnkey secret client")
		}
		plaintext, err := client.ExportSecret(ctx, cfg.OrganizationID, cfg.SecretID)
		defer clear(plaintext)
		if err != nil {
			// SDK errors can contain upstream response details. Keep them out of
			// lazy-source logs and proxy responses, including approval failures.
			return "", errors.New("turnkey secret export failed")
		}
		if len(plaintext) == 0 {
			return "", errors.New("turnkey secret is empty")
		}
		return string(plaintext), nil
	})
}

func newTurnkeyClient(organizationID, apiKeyEnv string) (turnkeyClient, error) {
	privateKey := os.Getenv(apiKeyEnv)
	if privateKey == "" {
		return nil, errors.New("turnkey API private key environment variable is not set or empty")
	}
	stamper, err := turnkey.NewAPIKeyStamper(privateKey)
	if err != nil {
		return nil, errors.New("invalid turnkey API private key")
	}
	client, err := turnkey.NewClient(stamper, organizationID,
		turnkey.WithHTTPClient(&http.Client{
			Timeout:   25 * time.Second,
			Transport: turnkeyTransport{inner: http.DefaultTransport},
		}),
		turnkey.WithHTTPRetries(0),
		// The SDK logs raw transport errors before we can sanitize them.
		turnkey.WithLogger(log.New(io.Discard, "", 0)),
	)
	if err != nil {
		return nil, errors.New("cannot initialize turnkey API client")
	}
	return client, nil
}

// The pinned SDK reconstructs http.Client and drops CheckRedirect. Reject
// redirects before net/http sees them, so no signed request can be replayed.
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
		return nil, errors.New("turnkey redirect rejected")
	}
	return resp, nil
}
