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
	"regexp"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem"
	turnkeycrypto "github.com/tkhq/go-sdk/crypto"
	turnkey "github.com/tkhq/go-sdk/v2"
	"gopkg.in/yaml.v3"
)

const turnkeyAPIPrivateKeyEnv = "TURNKEY_API_PRIVATE_KEY"

// turnkeyClient is the subset of *turnkey.Client the source uses. The source
// calls ExportSecrets directly, not the SDK's ExportSecret helper, so it can
// keep the recipient key of an export that is waiting for approval.
type turnkeyClient interface {
	ExportSecrets(ctx context.Context, input turnkey.ExportSecretsRequest) (*turnkey.ExportSecretsResponse, error)
	GetActivity(ctx context.Context, input turnkey.GetActivityRequest) (*turnkey.ActivityResponse, error)
}

type turnkeyBuilder struct {
	clientFor func(organizationID, apiKeyEnv string) (turnkeyClient, error)
	logger    *slog.Logger
	// signerKey overrides the production Signer key. Tests only.
	signerKey *ecdsa.PublicKey
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
	if err := raw.Decode(&cfg); err != nil {
		// yaml errors can quote the offending value; keep it out of logs.
		return nil, errors.New("invalid turnkey source configuration")
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
	export := &turnkeyExport{builder: b, organizationID: cfg.OrganizationID, secretID: cfg.SecretID, apiKeyEnv: cfg.APIPrivateKeyEnv}
	return buildLazySource("turnkey:"+cfg.OrganizationID+"/"+cfg.SecretID, cfg.TTL, cfg.FailureTTL, b.logger, func(ctx context.Context) (string, error) {
		plaintext, err := export.fetch(ctx)
		defer clear(plaintext)
		if err != nil {
			return "", err
		}
		if len(plaintext) == 0 {
			return "", errors.New("turnkey secret is empty")
		}
		return string(plaintext), nil
	})
}

// turnkeyExport is the fetch state of one source. cachedValue holds its lock
// for the whole fetch, so fetch calls for one source never run concurrently.
//
// When an export needs approval, the source keeps the activity ID and the
// recipient private key. Later fetches read that activity instead of
// submitting a new export, so one approval completes the export and retries
// do not add new pending activities.
type turnkeyExport struct {
	builder                             *turnkeyBuilder
	organizationID, secretID, apiKeyEnv string
	pendingActivityID                   string
	pendingKey                          kem.PrivateKey
}

func (e *turnkeyExport) fetch(ctx context.Context) ([]byte, error) {
	client, err := e.builder.clientFor(e.organizationID, e.apiKeyEnv)
	if err != nil {
		return nil, errors.New("turnkey secret client initialization failed")
	}
	if e.pendingActivityID != "" {
		return e.resume(ctx, client)
	}
	targetPublicKey, kemPrivate, err := turnkeycrypto.GenerateEncryptionKeyPair()
	if err != nil {
		return nil, errors.New("cannot generate turnkey export recipient key")
	}
	res, err := client.ExportSecrets(ctx, turnkey.ExportSecretsRequest{
		OrganizationID: e.organizationID,
		Secrets: []turnkey.ExportSecretParams{{
			SecretID:        e.secretID,
			TargetPublicKey: targetPublicKey,
			EncryptionSuite: turnkey.TransportEncryptionSuiteEnclaveEncryptV1,
		}},
	})
	if err != nil {
		var approval *turnkey.ActivityRequiresApprovalError
		if errors.As(err, &approval) && approval.ActivityID != "" {
			e.pendingActivityID, e.pendingKey = approval.ActivityID, kemPrivate
		}
		// SDK errors can contain upstream response details. Keep them out of
		// lazy-source logs and proxy responses.
		return nil, sanitizeTurnkeyError(err)
	}
	return e.decrypt(res.ExportSecretsResult.SecretPayloads, kemPrivate)
}

// resume reads the pending export activity. It does not submit a new export.
func (e *turnkeyExport) resume(ctx context.Context, client turnkeyClient) ([]byte, error) {
	activityID := e.pendingActivityID
	res, err := client.GetActivity(ctx, turnkey.GetActivityRequest{OrganizationID: e.organizationID, ActivityID: activityID})
	if err != nil {
		var request *turnkey.RequestError
		if errors.As(err, &request) && request.StatusCode == http.StatusNotFound {
			e.clearPending()
		}
		return nil, sanitizeTurnkeyError(err)
	}
	activity := res.Activity
	switch activity.Status {
	case turnkey.ActivityStatusCompleted:
		key := e.pendingKey
		e.clearPending()
		if activity.Result.ExportSecretsResult == nil {
			return nil, sanitizeTurnkeyError(errors.New("completed export has no result"))
		}
		return e.decrypt(activity.Result.ExportSecretsResult.SecretPayloads, key)
	case turnkey.ActivityStatusConsensusNeeded, turnkey.ActivityStatusAuthenticatorsNeeded,
		turnkey.ActivityStatusPending, turnkey.ActivityStatusCreated:
		return nil, sanitizeTurnkeyError(&turnkey.ActivityRequiresApprovalError{ActivityID: activityID})
	default:
		// Rejected, failed, or unknown. The next fetch submits a new export.
		e.clearPending()
		return nil, sanitizeTurnkeyError(&turnkey.ActivityFailedError{ActivityID: activityID, Status: activity.Status})
	}
}

func (e *turnkeyExport) clearPending() {
	e.pendingActivityID, e.pendingKey = "", nil
}

func (e *turnkeyExport) decrypt(payloads []string, key kem.PrivateKey) ([]byte, error) {
	if len(payloads) != 1 {
		return nil, sanitizeTurnkeyError(fmt.Errorf("expected one export payload, got %d", len(payloads)))
	}
	var signerKey []*ecdsa.PublicKey
	if e.builder.signerKey != nil {
		signerKey = append(signerKey, e.builder.signerKey)
	}
	plaintext, err := turnkeycrypto.DecryptExportBundle([]byte(payloads[0]), e.organizationID, key, signerKey...)
	if err != nil {
		return nil, sanitizeTurnkeyError(err)
	}
	return plaintext, nil
}

func newTurnkeyClient(organizationID, apiKeyEnv string) (turnkeyClient, error) {
	client, err := newTurnkeySDKClient(organizationID, apiKeyEnv, http.DefaultTransport)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Internal dependency injection keeps test endpoints out of source configuration.
func newTurnkeySDKClient(organizationID, apiKeyEnv string, transport http.RoundTripper, options ...turnkey.OptionFunc) (*turnkey.Client, error) {
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
			// Three attempts plus backoff must fit in the 30-second fetch deadline.
			Timeout:   8 * time.Second,
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

var turnkeyActivityIDPattern = regexp.MustCompile(`^[0-9a-fA-F-]{1,64}$`)

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
		// The activity ID is not secret. Operators need it to find the
		// activity to approve. Include it only if it has the expected form.
		if turnkeyActivityIDPattern.MatchString(approval.ActivityID) {
			return fmt.Errorf("turnkey secret export failed (approval_required, activity %s)", approval.ActivityID)
		}
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
