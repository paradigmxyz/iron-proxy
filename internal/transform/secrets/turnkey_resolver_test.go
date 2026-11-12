package secrets

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	turnkey "github.com/tkhq/go-sdk/v2"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// turnkeyFakeSigner signs fake export bundles. Builders in tests trust it
// through signerKey, so fakes still go through real decryption.
var turnkeyFakeSigner = func() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}()

type fakeTurnkeyClient struct {
	export   func(context.Context, string, string) ([]byte, error)
	activity func(context.Context, string) (*turnkey.ActivityResponse, error)
}

func (c fakeTurnkeyClient) ExportSecrets(ctx context.Context, input turnkey.ExportSecretsRequest) (*turnkey.ExportSecretsResponse, error) {
	param := input.Secrets[0]
	plaintext, err := c.export(ctx, input.OrganizationID, param.SecretID)
	if err != nil {
		return nil, err
	}
	bundle, err := signTurnkeyTestExport(turnkeyFakeSigner, param.TargetPublicKey, input.OrganizationID, plaintext, false)
	if err != nil {
		return nil, err
	}
	return &turnkey.ExportSecretsResponse{ExportSecretsResult: turnkey.ExportSecretsResult{SecretPayloads: []string{bundle}}}, nil
}

func (c fakeTurnkeyClient) GetActivity(ctx context.Context, input turnkey.GetActivityRequest) (*turnkey.ActivityResponse, error) {
	if c.activity == nil {
		return nil, errors.New("unexpected activity read")
	}
	return c.activity(ctx, input.ActivityID)
}

func TestTurnkeyBuilderLazyExport(t *testing.T) {
	for _, keyEnv := range []string{"", "CUSTOM_TURNKEY_KEY"} {
		t.Run("key_env="+keyEnv, func(t *testing.T) {
			clientCalls, exportCalls := 0, 0
			plaintext := []byte("test-only-upstream-credential")
			var logs bytes.Buffer
			builder := &turnkeyBuilder{signerKey: &turnkeyFakeSigner.PublicKey,
				logger: slog.New(slog.NewJSONHandler(&logs, nil)),
				clientFor: func(org, env string) (turnkeyClient, error) {
					clientCalls++
					require.Equal(t, "test-org", org)
					expectedEnv := keyEnv
					if expectedEnv == "" {
						expectedEnv = turnkeyAPIPrivateKeyEnv
					}
					require.Equal(t, expectedEnv, env)
					return fakeTurnkeyClient{export: func(_ context.Context, org, secret string) ([]byte, error) {
						exportCalls++
						require.Equal(t, "test-org", org)
						require.Equal(t, "test-secret", secret)
						return plaintext, nil
					}}, nil
				},
			}
			source, err := builder.Build(yamlNode(t, map[string]string{
				"organization_id": "test-org", "secret_id": "test-secret",
				"api_private_key_env": keyEnv, "ttl": "1m", "failure_ttl": "2s",
			}))
			require.NoError(t, err)
			require.Zero(t, clientCalls)
			require.Zero(t, exportCalls)
			require.Equal(t, "turnkey:test-org/test-secret", source.Name())
			for range 2 {
				value, err := source.Get(context.Background())
				require.NoError(t, err)
				require.Equal(t, "test-only-upstream-credential", value)
			}
			require.Equal(t, 1, clientCalls)
			require.Equal(t, 1, exportCalls)
			require.NotContains(t, logs.String(), "test-only-upstream-credential")
		})
	}
}

func TestTurnkeyBuilderValidationDoesNotFetch(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]any
	}{
		{name: "missing organization", cfg: map[string]any{"secret_id": "test-secret"}},
		{name: "missing secret", cfg: map[string]any{"organization_id": "test-org"}},
		{name: "invalid organization type", cfg: map[string]any{"organization_id": []string{"invalid"}, "secret_id": "test-secret"}},
		{name: "invalid ttl", cfg: map[string]any{"organization_id": "test-org", "secret_id": "test-secret", "ttl": "invalid"}},
		{name: "invalid failure ttl", cfg: map[string]any{"organization_id": "test-org", "secret_id": "test-secret", "failure_ttl": "invalid"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			builder := &turnkeyBuilder{signerKey: &turnkeyFakeSigner.PublicKey,
				logger: slog.Default(),
				clientFor: func(string, string) (turnkeyClient, error) {
					t.Fatal("validation must not create a client")
					return nil, nil
				},
			}
			_, err := builder.Build(yamlNode(t, tc.cfg))
			require.Error(t, err)
		})
	}
}

func TestTurnkeyBuilderFailuresDoNotExposeSecrets(t *testing.T) {
	cases := []struct {
		name      string
		clientErr error
		exportErr error
		plaintext []byte
	}{
		{name: "client", clientErr: errors.New("sensitive-backend-detail")},
		{name: "export", exportErr: errors.New("sensitive-backend-detail"), plaintext: []byte("sensitive-backend-detail")},
		{name: "approval", exportErr: &turnkey.ActivityRequiresApprovalError{ActivityID: "test-activity"}},
		{name: "empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			builder := &turnkeyBuilder{signerKey: &turnkeyFakeSigner.PublicKey,
				logger: slog.New(slog.NewJSONHandler(&logs, nil)),
				clientFor: func(string, string) (turnkeyClient, error) {
					return fakeTurnkeyClient{export: func(context.Context, string, string) ([]byte, error) {
						return tc.plaintext, tc.exportErr
					}}, tc.clientErr
				},
			}
			source, err := builder.Build(yamlNode(t, map[string]string{"organization_id": "test-org", "secret_id": "test-secret"}))
			require.NoError(t, err)
			value, err := source.Get(context.Background())
			require.Error(t, err)
			require.Empty(t, value)
			require.NotContains(t, err.Error(), "sensitive-backend-detail")
			require.NotContains(t, logs.String(), "sensitive-backend-detail")
		})
	}
}

func TestNewTurnkeyClientDoesNotExposeInvalidKey(t *testing.T) {
	for _, key := range []string{"", "invalid-test-only-key"} {
		t.Run("key="+key, func(t *testing.T) {
			t.Setenv("TEST_TURNKEY_KEY", key)
			_, err := newTurnkeyClient("test-org", "TEST_TURNKEY_KEY")
			require.Error(t, err)
			require.NotContains(t, err.Error(), "invalid-test-only-key")
		})
	}
}

func TestTurnkeyFactoryRejectsRequiredUnavailableSecret(t *testing.T) {
	t.Setenv("EMPTY_TEST_TURNKEY_KEY", "")
	tr, err := factory(yamlNode(t, map[string]any{
		"secrets": []any{map[string]any{
			"source": map[string]any{
				"type": "turnkey", "organization_id": "test-org", "secret_id": "test-secret",
				"api_private_key_env": "EMPTY_TEST_TURNKEY_KEY",
			},
			"replace": map[string]any{
				"proxy_value": "test-proxy-token", "match_headers": []string{"Authorization"}, "require": true,
			},
			"rules": []any{map[string]any{"host": "example.test"}},
		}},
	}), slog.Default())
	require.NoError(t, err)
	req := httptest.NewRequest("GET", "https://example.test/", nil)
	req.Header.Set("Authorization", "Bearer test-proxy-token")
	result, err := tr.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, result.Action)
}

// Exercise the real SDK and net/http redirect machinery, not fakeTurnkeyClient.
func TestTurnkeyClientRejectsRedirects(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			calls := 0
			body := &trackedTurnkeyBody{Reader: strings.NewReader("redirect")}
			transport := turnkeyRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls > 1 {
					return nil, errors.New("redirect target reached")
				}
				require.Equal(t, "POST", req.Method)
				require.NotEmpty(t, req.Header.Get("X-Stamp"))
				return &http.Response{StatusCode: status, Header: http.Header{"Location": {"https://redirect.invalid/export"}}, Body: body, Request: req}, nil
			})
			t.Setenv("TEST_TURNKEY_KEY", strings.Repeat("0", 63)+"1")
			client, err := newTurnkeySDKClient("test-org", "TEST_TURNKEY_KEY", transport)
			require.NoError(t, err)
			_, err = client.ExportSecret(context.Background(), "test-org", "test-secret")
			require.Error(t, err)
			require.Equal(t, 1, calls, "signed requests must never reach a redirect target")
			require.True(t, body.closed)
		})
	}
}

type turnkeyRoundTripFunc func(*http.Request) (*http.Response, error)

func (f turnkeyRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type trackedTurnkeyBody struct {
	*strings.Reader
	closed bool
}

func (b *trackedTurnkeyBody) Close() error { b.closed = true; return nil }

func TestTurnkeyApprovalFailureAfterSuccessServesStale(t *testing.T) {
	exports, reads := 0, 0
	builder := &turnkeyBuilder{signerKey: &turnkeyFakeSigner.PublicKey, logger: slog.Default(), clientFor: func(string, string) (turnkeyClient, error) {
		return fakeTurnkeyClient{
			export: func(context.Context, string, string) ([]byte, error) {
				exports++
				if exports == 1 {
					return []byte("synthetic-cached-secret"), nil
				}
				return nil, &turnkey.ActivityRequiresApprovalError{ActivityID: "test-activity"}
			},
			activity: func(_ context.Context, id string) (*turnkey.ActivityResponse, error) {
				reads++
				require.Equal(t, "test-activity", id)
				return &turnkey.ActivityResponse{Activity: turnkey.Activity{ID: id, Status: turnkey.ActivityStatusConsensusNeeded}}, nil
			},
		}, nil
	}}
	source, err := builder.Build(yamlNode(t, map[string]string{"organization_id": "test-org", "secret_id": "test-secret", "ttl": "1m", "failure_ttl": "2s"}))
	require.NoError(t, err)
	cache := source.(*cachedValue)
	now := time.Now()
	cache.now = func() time.Time { return now }
	for range 4 {
		value, err := source.Get(context.Background())
		require.NoError(t, err)
		require.Equal(t, "synthetic-cached-secret", value)
		now = now.Add(time.Minute)
	}
	// One success, one export that needs approval, then reads of that activity.
	require.Equal(t, 2, exports)
	require.Equal(t, 2, reads)
}

func TestTurnkeyPendingExportOutcomes(t *testing.T) {
	cases := []struct {
		name       string
		status     turnkey.ActivityStatus
		readErr    error
		wantErr    string
		wantExport int
	}{
		{name: "still pending", status: turnkey.ActivityStatusConsensusNeeded, wantErr: "turnkey secret export failed (approval_required, activity 0000-abcd)", wantExport: 1},
		{name: "rejected", status: turnkey.ActivityStatusRejected, wantErr: "turnkey secret export failed (activity_failed)", wantExport: 2},
		{name: "not found", readErr: &turnkey.RequestError{StatusCode: 404}, wantErr: "turnkey secret export failed (not_found)", wantExport: 2},
		{name: "transient read failure", readErr: &turnkey.RequestError{StatusCode: 503}, wantErr: "turnkey secret export failed (service_unavailable)", wantExport: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exports := 0
			client := fakeTurnkeyClient{
				export: func(context.Context, string, string) ([]byte, error) {
					exports++
					return nil, &turnkey.ActivityRequiresApprovalError{ActivityID: "0000-abcd"}
				},
				activity: func(_ context.Context, id string) (*turnkey.ActivityResponse, error) {
					if tc.readErr != nil {
						return nil, tc.readErr
					}
					return &turnkey.ActivityResponse{Activity: turnkey.Activity{ID: id, Status: tc.status}}, nil
				},
			}
			builder := &turnkeyBuilder{signerKey: &turnkeyFakeSigner.PublicKey, logger: slog.Default(), clientFor: func(string, string) (turnkeyClient, error) { return client, nil }}
			source, err := builder.Build(yamlNode(t, map[string]string{"organization_id": "test-org", "secret_id": "test-secret"}))
			require.NoError(t, err)
			now := time.Now()
			source.(*cachedValue).now = func() time.Time { return now }
			_, err = source.Get(context.Background())
			require.EqualError(t, err, "turnkey secret export failed (approval_required, activity 0000-abcd)")
			now = now.Add(2 * time.Minute)
			_, err = source.Get(context.Background())
			require.EqualError(t, err, tc.wantErr)
			now = now.Add(2 * time.Minute)
			_, err = source.Get(context.Background())
			require.Error(t, err)
			require.Equal(t, tc.wantExport, exports)
		})
	}
}

func TestTurnkeyTransportFailureDoesNotLogDetails(t *testing.T) {
	originalStdout := os.Stdout
	capture, err := os.CreateTemp(t.TempDir(), "stdout")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Stdout = originalStdout
		require.NoError(t, capture.Close())
	})
	os.Stdout = capture
	calls := 0
	transport := turnkeyRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("sensitive-transport-detail")
	})
	t.Setenv("TEST_TURNKEY_KEY", strings.Repeat("0", 63)+"1")
	builder := &turnkeyBuilder{signerKey: &turnkeyFakeSigner.PublicKey, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), clientFor: func(org, env string) (turnkeyClient, error) { return newTurnkeySDKClient(org, env, transport) }}
	source, err := builder.Build(yamlNode(t, map[string]string{
		"organization_id": "test-org", "secret_id": "test-secret", "api_private_key_env": "TEST_TURNKEY_KEY",
	}))
	require.NoError(t, err)
	_, err = source.Get(context.Background())
	require.EqualError(t, err, "turnkey secret export failed (transport_failed)")
	require.Equal(t, 3, calls, "transport errors must stop after two retries")
	output, err := os.ReadFile(capture.Name())
	require.NoError(t, err)
	require.Empty(t, string(output))
}
