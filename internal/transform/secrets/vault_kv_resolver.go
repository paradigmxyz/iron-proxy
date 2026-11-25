package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	vaultapi "github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// vaultKVClient is the subset of Vault used by vaultKVBuilder, narrowed for
// testability and to keep KV version handling out of the source builder.
type vaultKVClient interface {
	ReadKV(ctx context.Context, mount, secretPath string, version int) (map[string]any, error)
}

// vaultKVBuilder reads static secrets from Vault KV v1 or v2. Authentication,
// address, namespace, and TLS configuration use the standard VAULT_*
// environment variables understood by the official Vault API client.
type vaultKVBuilder struct {
	clientFor func(context.Context) (vaultKVClient, error)
	logger    *slog.Logger
}

type vaultKVConfig struct {
	Type       string `yaml:"type"`
	Mount      string `yaml:"mount"`
	Path       string `yaml:"path"`
	KVVersion  int    `yaml:"kv_version,omitempty"`
	TTL        string `yaml:"ttl,omitempty"`
	FailureTTL string `yaml:"failure_ttl,omitempty"`
}

func (cfg vaultKVConfig) version() int {
	if cfg.KVVersion == 0 {
		return 2
	}
	return cfg.KVVersion
}

func newVaultKVBuilder(logger *slog.Logger) *vaultKVBuilder {
	cache := &vaultKVClientCache{
		newClient: func() (vaultKVClient, error) {
			var cfg *vaultapi.Config
			if dial := transform.OutboundDialer(); dial != nil {
				cfg = vaultapi.DefaultConfig()
				if cfg.Error != nil {
					return nil, cfg.Error
				}
				tr, ok := cfg.HttpClient.Transport.(*http.Transport)
				if !ok {
					return nil, fmt.Errorf("vault client transport is %T, want *http.Transport", cfg.HttpClient.Transport)
				}
				tr.DialContext = dial
				// An env proxy would hide the real destination from the guard.
				tr.Proxy = nil
			}
			client, err := vaultapi.NewClient(cfg)
			if err != nil {
				return nil, err
			}
			return vaultAPIKVClient{client: client}, nil
		},
	}
	return &vaultKVBuilder{clientFor: cache.get, logger: logger}
}

func (r *vaultKVBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg vaultKVConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing vault_kv source config: %w", err)
	}
	if cfg.Mount == "" {
		return nil, fmt.Errorf("vault_kv source requires \"mount\" field")
	}
	if cfg.Path == "" {
		return nil, fmt.Errorf("vault_kv source requires \"path\" field")
	}
	if version := cfg.version(); version != 1 && version != 2 {
		return nil, fmt.Errorf("vault_kv source kv_version must be 1 or 2, got %d", cfg.KVVersion)
	}

	secretPath := cfg.Mount + "/" + cfg.Path
	name := "vault_kv:" + secretPath
	return buildLazySource(name, cfg.TTL, cfg.FailureTTL, r.logger, func(ctx context.Context) (string, error) {
		client, err := r.clientFor(ctx)
		if err != nil {
			return "", fmt.Errorf("creating Vault client: %w", err)
		}
		data, err := client.ReadKV(ctx, cfg.Mount, cfg.Path, cfg.version())
		if err != nil {
			return "", fmt.Errorf("reading Vault KV secret %q: %w", secretPath, err)
		}
		if len(data) == 0 {
			return "", fmt.Errorf("vault KV secret %q resolved without data", secretPath)
		}
		value, err := json.Marshal(data)
		if err != nil {
			return "", fmt.Errorf("encoding Vault KV secret %q as JSON: %w", secretPath, err)
		}
		return string(value), nil
	})
}

// vaultKVClientCache lazily constructs one Vault client per builder. A builder
// is shared by all vault_kv entries in a transform pipeline, so the client's
// HTTP transport and connection pool are reused safely across entries.
type vaultKVClientCache struct {
	mu        sync.Mutex
	client    vaultKVClient
	newClient func() (vaultKVClient, error)
}

func (c *vaultKVClientCache) get(_ context.Context) (vaultKVClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, nil
	}
	client, err := c.newClient()
	if err != nil {
		return nil, err
	}
	c.client = client
	return c.client, nil
}

type vaultAPIKVClient struct {
	client *vaultapi.Client
}

func (c vaultAPIKVClient) ReadKV(ctx context.Context, mount, secretPath string, version int) (map[string]any, error) {
	var (
		secret *vaultapi.KVSecret
		err    error
	)
	if version == 1 {
		secret, err = c.client.KVv1(mount).Get(ctx, secretPath)
	} else {
		secret, err = c.client.KVv2(mount).Get(ctx, secretPath)
	}
	if err != nil {
		return nil, err
	}
	if secret.Data == nil {
		if secret.Raw != nil && len(secret.Raw.Warnings) > 0 {
			return nil, fmt.Errorf("secret resolved without data: %s", strings.Join(secret.Raw.Warnings, "; "))
		}
		return nil, fmt.Errorf("secret resolved without data")
	}
	return secret.Data, nil
}
