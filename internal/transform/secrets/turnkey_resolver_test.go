package secrets

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	turnkey "github.com/tkhq/go-sdk/v2"

	"github.com/ironsh/iron-proxy/internal/transform"
)

type fakeTurnkeyClient struct {
	export func(context.Context, string, string) ([]byte, error)
}

func (c fakeTurnkeyClient) ExportSecret(ctx context.Context, org, secret string, signerKey ...*ecdsa.PublicKey) ([]byte, error) {
	return c.export(ctx, org, secret)
}

func TestTurnkeyBuilderLazyExport(t *testing.T) {
	for _, keyEnv := range []string{"", "CUSTOM_TURNKEY_KEY"} {
		t.Run("key_env="+keyEnv, func(t *testing.T) {
			clientCalls, exportCalls := 0, 0
			plaintext := []byte("test-only-upstream-credential")
			var logs bytes.Buffer
			builder := &turnkeyBuilder{
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
			require.Equal(t, make([]byte, len(plaintext)), plaintext)
			require.NotContains(t, logs.String(), "test-only-upstream-credential")
		})
	}
}

func TestTurnkeyBuilderValidationDoesNotFetch(t *testing.T) {
	cases := []map[string]any{
		{"secret_id": "test-secret"},
		{"organization_id": "test-org"},
		{"organization_id": []string{"invalid"}, "secret_id": "test-secret"},
		{"organization_id": "test-org", "secret_id": "test-secret", "ttl": "invalid"},
		{"organization_id": "test-org", "secret_id": "test-secret", "failure_ttl": "invalid"},
	}
	for _, cfg := range cases {
		t.Run("invalid_config", func(t *testing.T) {
			builder := &turnkeyBuilder{
				logger: slog.Default(),
				clientFor: func(string, string) (turnkeyClient, error) {
					t.Fatal("validation must not create a client")
					return nil, nil
				},
			}
			_, err := builder.Build(yamlNode(t, cfg))
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
			builder := &turnkeyBuilder{
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
			if tc.plaintext != nil {
				require.Equal(t, make([]byte, len(tc.plaintext)), tc.plaintext)
			}
		})
	}
}

func TestNewTurnkeyClientDoesNotExposeInvalidKey(t *testing.T) {
	for _, key := range []string{"", "invalid-test-only-key"} {
		t.Run("invalid_key", func(t *testing.T) {
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
