// Package sshproxy implements an SSH credential boundary within iron-proxy.
package sshproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// Grant is delivered only over the authenticated proxy control channel.
type Grant struct {
	ID          string    `json:"id" yaml:"id"`
	Principal   string    `json:"principal" yaml:"principal"`
	Destination string    `json:"destination" yaml:"destination"`
	Generation  string    `json:"generation" yaml:"generation"`
	Username    string    `json:"username" yaml:"username"`
	HostKey     string    `json:"host_key" yaml:"host_key"`
	TLSIdentity bool      `json:"tls_identity,omitempty" yaml:"tls_identity"`
	PrivateKey  yaml.Node `json:"-" yaml:"private_key"`
	ExpiresAt   time.Time `json:"expires_at" yaml:"expires_at"`
}

// Authorization identifies a sandbox key and a configured route, never a user.
type Authorization struct {
	Route       string `json:"route"`
	PublicKey   string `json:"public_key"`
	Destination string `json:"destination,omitempty"`
}

// Authorizer is called again during active connections; errors revoke access.
type Authorizer func(context.Context, Authorization) (*Grant, error)

// HTTPAuthorizer uses a proxy-only bearer token and does not follow redirects.
func HTTPAuthorizer(endpoint, token string) Authorizer {
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(ctx context.Context, a Authorization) (*Grant, error) {
		body, err := json.Marshal(a)
		if err != nil {
			return nil, errors.New("authorization encoding failed")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, errors.New("authorization URL invalid")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, errors.New("authorization unavailable")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, errors.New("SSH access denied")
		}
		// JSON is decoded as YAML so source nodes retain the existing resolver contract.
		data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, errors.New("authorization response unavailable")
		}
		var g Grant
		if yaml.Unmarshal(data, &g) != nil {
			return nil, errors.New("invalid authorization response")
		}
		return &g, nil
	}
}

func signer(ctx context.Context, node yaml.Node, logger *slog.Logger) (ssh.Signer, error) {
	source, err := secrets.BuildSource(node, logger)
	if err != nil {
		return nil, errors.New("SSH credential source invalid")
	}
	value, err := source.Get(ctx)
	if err != nil {
		return nil, errors.New("SSH credential unavailable")
	}
	key, err := ssh.ParsePrivateKey([]byte(value))
	if err != nil {
		return nil, errors.New("SSH credential invalid")
	}
	return key, nil
}

// LoadFromNode prepares the optional SSH listener before other services start.
// An absent block disables SSH. The real key and bearer token stay in the proxy.
func LoadFromNode(ctx context.Context, node yaml.Node, logger *slog.Logger) (*Server, net.Listener, error) {
	if node.Kind == 0 || node.Tag == "!!null" {
		return nil, nil, nil
	}
	var cfg struct {
		Listen          string    `yaml:"listen"`
		HostKey         yaml.Node `yaml:"host_key"`
		ClientPublicKey string    `yaml:"client_public_key"`
		AuthorizeURL    string    `yaml:"authorize_url"`
		TokenEnv        string    `yaml:"token_env"`
		DenyCIDRs       []string  `yaml:"upstream_deny_cidrs"`
	}
	if node.Decode(&cfg) != nil || cfg.Listen == "" || cfg.AuthorizeURL == "" {
		return nil, nil, errors.New("SSH listen address and authorization URL required")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	host, err := ParseHostKey(ctx, cfg.HostKey, logger)
	if err != nil {
		return nil, nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.ClientPublicKey))
	if err != nil {
		return nil, nil, errors.New("sandbox SSH public key invalid")
	}
	token := os.Getenv(cfg.TokenEnv)
	if token == "" {
		return nil, nil, errors.New("SSH proxy token unavailable")
	}
	if cfg.DenyCIDRs == nil {
		cfg.DenyCIDRs = dnsguard.DefaultDenyCIDRs
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return nil, nil, errors.New("SSH listener unavailable")
	}
	server := &Server{HostKey: host, ClientPublicKey: key, Authorize: HTTPAuthorizer(cfg.AuthorizeURL, token), DenyCIDRs: cfg.DenyCIDRs, Logger: logger}
	return server, listener, nil
}
