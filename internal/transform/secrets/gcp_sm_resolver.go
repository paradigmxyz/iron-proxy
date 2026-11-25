package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sync"

	"github.com/cenkalti/backoff/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"
)

// gcpSMMaxResponseBytes caps the :access response body. Secret payloads are
// limited to 64 KiB, so base64 and JSON framing fit well within 1 MiB.
const gcpSMMaxResponseBytes = 1 << 20

// Fields are interpolated into the request URL, and location into the
// hostname, so these patterns are the injection boundary: no '/', '?', '#',
// or '%' anywhere, and no '.' in location.
var (
	gcpSMProjectPattern  = regexp.MustCompile(`^(?:[a-z0-9.-]+:)?[a-z0-9][a-z0-9-]*$`)
	gcpSMSecretPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
	gcpSMVersionPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)
	gcpSMLocationPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
)

// gcpSMBuilder reads secrets from Google Cloud Secret Manager through its
// REST API, authenticating with Application Default Credentials.
type gcpSMBuilder struct {
	clientFor func(context.Context) (*http.Client, error)
	endpoint  func(location string) string
	logger    *slog.Logger
}

type gcpSMConfig struct {
	Type       string `yaml:"type"`
	Project    string `yaml:"project"`
	Secret     string `yaml:"secret"`
	Version    string `yaml:"version,omitempty"`
	Location   string `yaml:"location,omitempty"`
	TTL        string `yaml:"ttl,omitempty"`
	FailureTTL string `yaml:"failure_ttl,omitempty"`
}

func newGCPSMBuilder(logger *slog.Logger) *gcpSMBuilder {
	cache := &gcpSMClientCache{}
	return &gcpSMBuilder{clientFor: cache.get, endpoint: gcpSMEndpoint, logger: logger}
}

func (r *gcpSMBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg gcpSMConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing gcp_sm source config: %w", err)
	}
	if cfg.Project == "" {
		return nil, fmt.Errorf("gcp_sm source requires \"project\" field")
	}
	if cfg.Secret == "" {
		return nil, fmt.Errorf("gcp_sm source requires \"secret\" field")
	}
	if cfg.Version == "" {
		cfg.Version = "latest"
	}
	if !gcpSMProjectPattern.MatchString(cfg.Project) {
		return nil, fmt.Errorf("gcp_sm source has invalid project %q", cfg.Project)
	}
	if !gcpSMSecretPattern.MatchString(cfg.Secret) {
		return nil, fmt.Errorf("gcp_sm source has invalid secret %q", cfg.Secret)
	}
	if !gcpSMVersionPattern.MatchString(cfg.Version) {
		return nil, fmt.Errorf("gcp_sm source has invalid version %q", cfg.Version)
	}
	if cfg.Location != "" && !gcpSMLocationPattern.MatchString(cfg.Location) {
		return nil, fmt.Errorf("gcp_sm source has invalid location %q", cfg.Location)
	}

	name := "projects/" + cfg.Project
	if cfg.Location != "" {
		name += "/locations/" + cfg.Location
	}
	name += "/secrets/" + cfg.Secret + "/versions/" + cfg.Version
	url := r.endpoint(cfg.Location) + "/v1/" + name + ":access"

	return buildLazySource("gcp_sm:"+name, cfg.TTL, cfg.FailureTTL, r.logger, func(ctx context.Context) (string, error) {
		client, err := r.clientFor(ctx)
		if err != nil {
			return "", fmt.Errorf("creating GCP Secret Manager client: %w", err)
		}
		val, err := backoff.Retry(ctx, func() (string, error) {
			return accessGCPSecret(ctx, client, url)
		}, backoff.WithMaxTries(3))
		if err != nil {
			return "", fmt.Errorf("accessing GCP secret %q: %w", name, err)
		}
		if val == "" {
			return "", fmt.Errorf("GCP secret %q resolved to empty value", name)
		}
		return val, nil
	})
}

// gcpSMEndpoint returns the API origin for location. Regional secrets are
// served only by their regional endpoint.
func gcpSMEndpoint(location string) string {
	if location == "" {
		return "https://secretmanager.googleapis.com"
	}
	return "https://secretmanager." + location + ".rep.googleapis.com"
}

// accessGCPSecret makes one :access call. Transport errors, HTTP 429, and
// HTTP 5xx are returned for retry; every other failure is permanent.
func accessGCPSecret(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", backoff.Permanent(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, gcpSMMaxResponseBytes))
	if err != nil {
		return "", err
	}

	var out struct {
		Payload struct {
			Data []byte `json:"data"`
		} `json:"payload"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if resp.StatusCode != http.StatusOK {
		// The message is best-effort detail; a non-JSON body (e.g. from a
		// front end) leaves it empty and the status still identifies the failure.
		_ = json.Unmarshal(body, &out)
		err := fmt.Errorf("HTTP %d: %s", resp.StatusCode, out.Error.Message)
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			return "", err
		}
		return "", backoff.Permanent(err)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", backoff.Permanent(fmt.Errorf("decoding response: %w", err))
	}
	return string(out.Payload.Data), nil
}

// newGCPSMHTTPClient authenticates requests with ts and refuses redirects:
// oauth2.Transport attaches the bearer token to every request it sends,
// including a redirect to another host.
func newGCPSMHTTPClient(ts oauth2.TokenSource) *http.Client {
	client := oauth2.NewClient(context.Background(), ts)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

// gcpSMClientCache lazily builds one ADC-backed client per builder. Only a
// successful build is cached, so a transient ADC failure is retried on the
// next fetch.
type gcpSMClientCache struct {
	mu     sync.Mutex
	client *http.Client
}

func (c *gcpSMClientCache) get(context.Context) (*http.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, nil
	}
	// The token source keeps this context for every later token refresh, so
	// it must outlive the per-fetch context passed to get. oauth2.Transport
	// refreshes without a context, so the client timeout is what bounds it.
	tokenCtx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Timeout: fetchTimeout})
	creds, err := google.FindDefaultCredentials(tokenCtx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("loading GCP default credentials: %w", err)
	}
	c.client = newGCPSMHTTPClient(creds.TokenSource)
	return c.client, nil
}
