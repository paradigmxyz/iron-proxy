package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	turnkey "github.com/tkhq/go-sdk/v2"
)

func TestTurnkeyClientCacheConcurrentReuseAndScope(t *testing.T) {
	var calls atomic.Int32
	cache := &turnkeyClientCache{newClient: func(string, string) (turnkeyClient, error) {
		calls.Add(1)
		return &fakeTurnkeyClient{}, nil
	}}
	var wg sync.WaitGroup
	clients := make([]turnkeyClient, 32)
	errs := make([]error, 32)
	for i := range clients {
		wg.Go(func() { clients[i], errs[i] = cache.get("org", "KEY") })
	}
	wg.Wait()
	for i := range clients {
		require.NoError(t, errs[i])
		require.Same(t, clients[0], clients[i])
	}
	require.Equal(t, int32(1), calls.Load())
	for _, key := range [][2]string{{"other-org", "KEY"}, {"org", "OTHER_KEY"}} {
		client, err := cache.get(key[0], key[1])
		require.NoError(t, err)
		require.NotSame(t, clients[0], client)
	}
	require.Equal(t, int32(3), calls.Load())
}

func TestTurnkeyClientCacheRetriesFailedInitialization(t *testing.T) {
	calls := 0
	cache := &turnkeyClientCache{newClient: func(org, env string) (turnkeyClient, error) { calls++; return newTurnkeyClient(org, env) }}
	t.Setenv("TEST_TURNKEY_CACHE_KEY", "invalid")
	_, err := cache.get("org", "TEST_TURNKEY_CACHE_KEY")
	require.Error(t, err)
	t.Setenv("TEST_TURNKEY_CACHE_KEY", strings.Repeat("0", 63)+"1")
	first, err := cache.get("org", "TEST_TURNKEY_CACHE_KEY")
	require.NoError(t, err)
	// Signing configuration stays fixed until config reload/restart, not each export.
	t.Setenv("TEST_TURNKEY_CACHE_KEY", "invalid-again")
	second, err := cache.get("org", "TEST_TURNKEY_CACHE_KEY")
	require.NoError(t, err)
	require.Same(t, first, second)
	require.Equal(t, 2, calls)
}

func TestTurnkeyExportErrorCategories(t *testing.T) {
	detail := "sensitive-backend-detail"
	cases := []struct {
		name     string
		err      error
		category string
	}{
		// detail does not have the form of an activity ID, so it is not included.
		{"approval", &turnkey.ActivityRequiresApprovalError{ActivityID: detail}, "approval_required"},
		{"activity", &turnkey.ActivityFailedError{ActivityID: detail, Failure: &turnkey.RPCStatus{Message: &detail}}, "activity_failed"},
		{"deadline", context.DeadlineExceeded, "timeout"},
		{"cancel", context.Canceled, "canceled"},
		{"network", &url.Error{Op: detail, URL: detail, Err: errors.New(detail)}, "transport_failed"},
		{"unknown", errors.New(detail), "export_failed"},
	}
	for _, tc := range []struct {
		status   int
		category string
	}{{307, "redirect_rejected"}, {401, "authentication_failed"}, {403, "permission_denied"}, {404, "not_found"}, {429, "rate_limited"}, {503, "service_unavailable"}, {400, "request_failed"}} {
		cases = append(cases, struct {
			name     string
			err      error
			category string
		}{fmt.Sprint(tc.status), &turnkey.RequestError{StatusCode: tc.status, Body: []byte(detail), Status: &turnkey.RPCStatus{Message: &detail}}, tc.category})
	}
	err := sanitizeTurnkeyError(fmt.Errorf("%s: %w", detail, &turnkey.ActivityRequiresApprovalError{ActivityID: "33333333-3333-4333-8333-333333333333"}))
	require.EqualError(t, err, "turnkey secret export failed (approval_required, activity 33333333-3333-4333-8333-333333333333)")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := sanitizeTurnkeyError(fmt.Errorf("%s: %w", detail, tc.err))
			require.EqualError(t, err, "turnkey secret export failed ("+tc.category+")")
			require.NotContains(t, err.Error(), detail)
		})
	}
}

func TestTurnkeyHTTPRetriesPreserveSignedRequestAndStop(t *testing.T) {
	cases := []struct {
		name              string
		status, wantCalls int
	}{
		{"transport failure bounded", 0, 3}, {"server failure bounded", 503, 3}, {"denied not retried", 403, 1}, {"rate limit not retried by SDK", 429, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEST_TURNKEY_RETRY_KEY", strings.Repeat("0", 63)+"1")
			calls := 0
			var firstBody []byte
			var firstStamp string
			transport := turnkeyRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				require.NoError(t, req.Body.Close())
				if calls == 1 {
					firstBody = body
					firstStamp = req.Header.Get("X-Stamp")
				} else {
					require.Equal(t, firstBody, body)
					require.Equal(t, firstStamp, req.Header.Get("X-Stamp"))
				}
				require.NotEmpty(t, firstStamp)
				if tc.status == 0 {
					return nil, errors.New("sensitive transport error")
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(`{"message":"sensitive"}`)), Header: make(http.Header)}, nil
			})
			client, err := newTurnkeySDKClient("org", "TEST_TURNKEY_RETRY_KEY", transport)
			require.NoError(t, err)
			_, err = client.ExportSecret(context.Background(), "org", "secret")
			require.Error(t, err)
			require.Equal(t, tc.wantCalls, calls)
		})
	}
}

func TestTurnkeyHTTPRetryHonorsContext(t *testing.T) {
	t.Setenv("TEST_TURNKEY_RETRY_KEY", strings.Repeat("0", 63)+"1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	client, err := newTurnkeySDKClient("org", "TEST_TURNKEY_RETRY_KEY", turnkeyRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		cancel()
		return nil, errors.New("synthetic transport failure")
	}))
	require.NoError(t, err)
	_, err = client.ExportSecret(ctx, "org", "secret")
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, calls)
}

func TestTurnkeyConfigurationReportsFieldWithoutValue(t *testing.T) {
	cases := []struct{ name, field, value string }{
		{"organization required", "organization_id", ""}, {"secret required", "secret_id", ""},
		{"invalid ttl", "ttl", "sensitive-invalid-duration"}, {"negative ttl", "ttl", "-1s"},
		{"invalid failure ttl", "failure_ttl", "sensitive-invalid-duration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := map[string]string{"organization_id": "org", "secret_id": "secret"}
			cfg[tc.field] = tc.value
			_, err := newTurnkeyBuilder(slog.Default()).Build(yamlNode(t, cfg))
			require.ErrorContains(t, err, tc.field)
			require.NotContains(t, err.Error(), "sensitive-invalid-duration")
		})
	}
}

func TestTurnkeyBuilderReusesClientAcrossSourcesAndRefreshes(t *testing.T) {
	var clients, exports int
	cache := &turnkeyClientCache{newClient: func(string, string) (turnkeyClient, error) {
		clients++
		return &fakeTurnkeyClient{export: func(context.Context, string, string) ([]byte, error) { exports++; return []byte("synthetic"), nil }}, nil
	}}
	builder := &turnkeyBuilder{signerKey: &turnkeyFakeSigner.PublicKey, clientFor: cache.get, logger: slog.Default()}
	now := time.Now()
	for _, id := range []string{"one", "two"} {
		source, err := builder.Build(yamlNode(t, map[string]string{"organization_id": "org", "secret_id": id, "ttl": "1m"}))
		require.NoError(t, err)
		source.(*cachedValue).now = func() time.Time { return now }
		for range 2 {
			value, err := source.Get(context.Background())
			require.NoError(t, err)
			require.Equal(t, "synthetic", value)
			now = now.Add(time.Minute)
		}
	}
	require.Equal(t, 1, clients)
	require.Equal(t, 4, exports)
}

func TestTurnkeyConfigurationRejectsNonScalarFields(t *testing.T) {
	for _, field := range []string{"organization_id", "secret_id", "api_private_key_env", "ttl", "failure_ttl"} {
		t.Run(field, func(t *testing.T) {
			cfg := map[string]any{"organization_id": "org", "secret_id": "secret"}
			cfg[field] = []string{"sensitive-value"}
			_, err := newTurnkeyBuilder(slog.Default()).Build(yamlNode(t, cfg))
			require.EqualError(t, err, "invalid turnkey source configuration")
		})
	}
}

// Other sources accept plain YAML integers such as ttl: 0. Turnkey matches them.
func TestTurnkeyConfigurationAcceptsIntegerTTL(t *testing.T) {
	_, err := newTurnkeyBuilder(slog.Default()).Build(yamlNode(t, map[string]any{
		"organization_id": "org", "secret_id": "secret", "ttl": 0, "failure_ttl": 0,
	}))
	require.NoError(t, err)
}

func TestTurnkeySourcesShareOneClientAcrossRegistries(t *testing.T) {
	// Separate transforms and config reloads each build their own registry.
	// They must still share one client per organization and key env.
	var calls atomic.Int32
	saved := turnkeyClients
	turnkeyClients = &turnkeyClientCache{newClient: func(string, string) (turnkeyClient, error) {
		calls.Add(1)
		return fakeTurnkeyClient{export: func(context.Context, string, string) ([]byte, error) { return []byte("synthetic"), nil }}, nil
	}}
	t.Cleanup(func() { turnkeyClients = saved })
	for _, id := range []string{"one", "two", "three"} {
		src, err := BuildSource(yamlNode(t, map[string]string{"type": "turnkey", "organization_id": "org", "secret_id": id}), slog.Default())
		require.NoError(t, err)
		// BuildSource trusts only the production Signer, so the fake bundle
		// fails decryption. The client is still created before that step.
		_, err = src.Get(context.Background())
		require.Error(t, err)
	}
	require.Equal(t, int32(1), calls.Load())
}
