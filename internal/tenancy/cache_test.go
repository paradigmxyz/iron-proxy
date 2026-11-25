package tenancy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mu sync.Mutex
	at time.Time
}

func newFakeClock(at time.Time) *fakeClock {
	return &fakeClock{at: at}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func countingBuilder(calls *atomic.Int32) Builder {
	return func(rules, secrets, transforms json.RawMessage) (*transform.Pipeline, error) {
		calls.Add(1)
		return transform.NewPipeline(nil, transform.BodyLimits{}, discardLogger()), nil
	}
}

func tenantToken(t *testing.T, priv ed25519.PrivateKey, subject, id string, now time.Time) string {
	t.Helper()
	return signJWT(t, priv, map[string]any{
		"iss": testIssuer,
		"sub": subject,
		"aud": testAudience,
		"exp": float64(now.Add(time.Hour).Unix()),
		"jti": id,
	})
}

const testControlPlaneToken = "proxy-control-plane-token"

type configControlPlane struct {
	server *httptest.Server

	mu     sync.Mutex
	calls  int
	auths  []string
	tokens []string
	hashes []string
}

func newConfigControlPlane(t *testing.T, respond func(call int, req configRequest) (int, string)) *configControlPlane {
	t.Helper()
	cp := &configControlPlane{}
	cp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req configRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		auth := r.Header.Get("Authorization")
		cp.mu.Lock()
		cp.calls++
		call := cp.calls
		cp.auths = append(cp.auths, auth)
		cp.tokens = append(cp.tokens, r.Header.Get(TenantTokenHeader))
		cp.hashes = append(cp.hashes, req.ConfigHash)
		cp.mu.Unlock()
		// The endpoint is authenticated as the proxy; the tenant token in its
		// header only selects whose config is returned.
		if auth != "Bearer "+testControlPlaneToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		status, body := respond(call, req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		// The client is the cache under test; a write failure is irrelevant here.
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(cp.server.Close)
	return cp
}

func (cp *configControlPlane) Calls() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.calls
}

func (cp *configControlPlane) Auths() []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return append([]string(nil), cp.auths...)
}

func (cp *configControlPlane) Tokens() []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return append([]string(nil), cp.tokens...)
}

func (cp *configControlPlane) Hashes() []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return append([]string(nil), cp.hashes...)
}

func fullConfigBody(hash string) string {
	return fmt.Sprintf(`{"config_hash":%q,"rules":[],"secrets":[],"transforms":[]}`, hash)
}

func hashOnlyConfigBody(hash string) string {
	return fmt.Sprintf(`{"config_hash":%q}`, hash)
}

type cacheFixture struct {
	cache      *Cache
	clock      *fakeClock
	buildCalls *atomic.Int32
}

func newCacheFixture(t *testing.T, url string, pub ed25519.PublicKey, freshFor, staleFor time.Duration) *cacheFixture {
	t.Helper()
	clock := newFakeClock(testEpoch)
	verifier := NewVerifier([]ed25519.PublicKey{pub}, testIssuer, testAudience)
	verifier.now = clock.Now
	buildCalls := &atomic.Int32{}
	cache := New(Options{
		Verifier:          verifier,
		URL:               url,
		ControlPlaneToken: testControlPlaneToken,
		FreshFor:          freshFor,
		StaleFor:          staleFor,
		Build:             countingBuilder(buildCalls),
		Logger:            discardLogger(),
	})
	cache.now = clock.Now
	return &cacheFixture{cache: cache, clock: clock, buildCalls: buildCalls}
}

func TestCacheBindRejectsBadCredentials(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKey(t)
	valid := tenantToken(t, priv, "tenant-a", "id-a", testEpoch)

	tests := []struct {
		name   string
		header string
		want   *Rejection
	}{
		{name: "missing", header: "", want: rejectTokenRequired},
		{name: "wrong scheme", header: "Basic abc", want: rejectTokenRequired},
		{name: "not a jwt", header: "Bearer not-a-jwt", want: rejectTokenInvalid},
		{name: "bad signature", header: "Bearer " + tamperClaims(t, valid, func(c map[string]any) {
			c["sub"] = "tenant-b"
		}), want: rejectTokenInvalid},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cp := newConfigControlPlane(t, func(int, configRequest) (int, string) {
				return http.StatusOK, fullConfigBody("hash-1")
			})
			f := newCacheFixture(t, cp.server.URL, pub, time.Minute, 10*time.Minute)

			ten, rej := f.cache.Bind(context.Background(), tc.header)
			require.Nil(t, ten)
			require.Same(t, tc.want, rej)
			require.Equal(t, http.StatusProxyAuthRequired, rej.Status)
			require.True(t, rej.Challenge)
			require.Equal(t, 0, cp.Calls())
		})
	}
}

func TestCacheBindFetchesAndRefreshes(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKey(t)
	raw := tenantToken(t, priv, "tenant-a", "id-a", testEpoch)
	cp := newConfigControlPlane(t, func(call int, req configRequest) (int, string) {
		if call == 1 {
			return http.StatusOK, fullConfigBody("hash-1")
		}
		return http.StatusOK, hashOnlyConfigBody("hash-1")
	})
	f := newCacheFixture(t, cp.server.URL, pub, time.Minute, 10*time.Minute)

	ten, rej := f.cache.Bind(context.Background(), "Bearer "+raw)
	require.Nil(t, rej)
	require.NotNil(t, ten)
	require.Equal(t, "tenant-a", ten.Token.Subject)
	require.Equal(t, raw, ten.Token.Raw)
	require.NotNil(t, ten.Pipeline)
	require.Equal(t, int32(1), f.buildCalls.Load())
	require.Equal(t, []string{"Bearer " + testControlPlaneToken}, cp.Auths())
	require.Equal(t, []string{raw}, cp.Tokens())
	require.Equal(t, []string{""}, cp.Hashes())

	f.clock.Advance(30 * time.Second)
	again, rej := f.cache.Bind(context.Background(), "Bearer "+raw)
	require.Nil(t, rej)
	require.Same(t, ten.Pipeline, again.Pipeline)
	require.Equal(t, 1, cp.Calls())
	require.Equal(t, int32(1), f.buildCalls.Load())

	// Past FreshFor: refresh conditionally with the hash we already have. A
	// hash-only 200 keeps the existing pipeline.
	f.clock.Advance(31 * time.Second)
	refreshed, rej := f.cache.Bind(context.Background(), "Bearer "+raw)
	require.Nil(t, rej)
	require.Same(t, ten.Pipeline, refreshed.Pipeline)
	require.Equal(t, 2, cp.Calls())
	require.Equal(t, []string{raw, raw}, cp.Tokens())
	require.Equal(t, []string{"", "hash-1"}, cp.Hashes())
	require.Equal(t, int32(1), f.buildCalls.Load())
}

func TestCacheSharesPipelineAcrossTokens(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKey(t)
	rawA := tenantToken(t, priv, "tenant-a", "id-a", testEpoch)
	rawB := tenantToken(t, priv, "tenant-b", "id-b", testEpoch)
	cp := newConfigControlPlane(t, func(int, configRequest) (int, string) {
		return http.StatusOK, fullConfigBody("shared")
	})
	f := newCacheFixture(t, cp.server.URL, pub, time.Minute, 10*time.Minute)

	a, rej := f.cache.Bind(context.Background(), "Bearer "+rawA)
	require.Nil(t, rej)
	b, rej := f.cache.Bind(context.Background(), "Bearer "+rawB)
	require.Nil(t, rej)
	require.Same(t, a.Pipeline, b.Pipeline)
	require.Equal(t, int32(1), f.buildCalls.Load())
	require.Equal(t, 2, cp.Calls())
	require.Equal(t, []string{"Bearer " + testControlPlaneToken, "Bearer " + testControlPlaneToken}, cp.Auths())
	require.Equal(t, []string{rawA, rawB}, cp.Tokens())
	require.Equal(t, []string{"", ""}, cp.Hashes())
}

func TestCacheRefusesTenant(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKey(t)
	tests := []struct {
		name   string
		status int
		want   *Rejection
	}{
		// 401 means the control plane refused the proxy's own credential, so
		// it is an availability failure, not a statement about the tenant.
		{name: "proxy credential refused", status: http.StatusUnauthorized, want: rejectUnavailable},
		{name: "forbidden", status: http.StatusForbidden, want: rejectTenant},
		{name: "not found", status: http.StatusNotFound, want: rejectTenant},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw := tenantToken(t, priv, "tenant-a", "id-a", testEpoch)
			cp := newConfigControlPlane(t, func(int, configRequest) (int, string) {
				return tc.status, ""
			})
			f := newCacheFixture(t, cp.server.URL, pub, time.Minute, 10*time.Minute)

			ten, rej := f.cache.Bind(context.Background(), "Bearer "+raw)
			require.Nil(t, ten)
			require.Same(t, tc.want, rej)
			require.Equal(t, tc.want.Status, rej.Status)
			require.Equal(t, 1, cp.Calls())

			// The failure or refusal is remembered for negativeFor: a revoked
			// token or unreachable control plane is not contacted on every
			// CONNECT.
			ten, rej = f.cache.Bind(context.Background(), "Bearer "+raw)
			require.Nil(t, ten)
			require.Same(t, tc.want, rej)
			require.Equal(t, 1, cp.Calls())

			// Then the control plane is asked again.
			f.clock.Advance(negativeFor)
			ten, rej = f.cache.Bind(context.Background(), "Bearer "+raw)
			require.Nil(t, ten)
			require.Same(t, tc.want, rej)
			require.Equal(t, 2, cp.Calls())
		})
	}
}

func TestCacheServesStalePipelineOnError(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKey(t)

	tests := []struct {
		name   string
		status int
	}{
		{name: "control plane error", status: http.StatusInternalServerError},
		{name: "proxy credential refused", status: http.StatusUnauthorized},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw := tenantToken(t, priv, "tenant-a", "id-a", testEpoch)
			cp := newConfigControlPlane(t, func(call int, req configRequest) (int, string) {
				if call == 1 {
					return http.StatusOK, fullConfigBody("hash-1")
				}
				return tc.status, ""
			})
			f := newCacheFixture(t, cp.server.URL, pub, time.Minute, 10*time.Minute)

			first, rej := f.cache.Bind(context.Background(), "Bearer "+raw)
			require.Nil(t, rej)
			require.NotNil(t, first.Pipeline)

			f.clock.Advance(2 * time.Minute)
			stale, rej := f.cache.Bind(context.Background(), "Bearer "+raw)
			require.Nil(t, rej)
			require.Same(t, first.Pipeline, stale.Pipeline)
			require.Equal(t, 2, cp.Calls())
			require.Equal(t, int32(1), f.buildCalls.Load())
		})
	}
}

func TestCacheUnavailableIsNegativeCached(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKey(t)
	raw := tenantToken(t, priv, "tenant-a", "id-a", testEpoch)
	cp := newConfigControlPlane(t, func(int, configRequest) (int, string) {
		return http.StatusInternalServerError, ""
	})
	f := newCacheFixture(t, cp.server.URL, pub, time.Minute, 10*time.Minute)

	ten, rej := f.cache.Bind(context.Background(), "Bearer "+raw)
	require.Nil(t, ten)
	require.Same(t, rejectUnavailable, rej)
	require.Equal(t, 1, cp.Calls())
	require.Equal(t, int32(0), f.buildCalls.Load())

	// Inside negativeFor the failure is remembered without another fetch.
	f.clock.Advance(2 * time.Second)
	ten, rej = f.cache.Bind(context.Background(), "Bearer "+raw)
	require.Nil(t, ten)
	require.Same(t, rejectUnavailable, rej)
	require.Equal(t, 1, cp.Calls())

	// Past negativeFor the proxy tries the control plane again.
	f.clock.Advance(4 * time.Second)
	ten, rej = f.cache.Bind(context.Background(), "Bearer "+raw)
	require.Nil(t, ten)
	require.Same(t, rejectUnavailable, rej)
	require.Equal(t, 2, cp.Calls())
	require.Equal(t, int32(0), f.buildCalls.Load())
}

func TestCacheUnavailableIsNegativeCachedAfterStaleExpiry(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKey(t)
	raw := tenantToken(t, priv, "tenant-a", "id-a", testEpoch)
	cp := newConfigControlPlane(t, func(call int, req configRequest) (int, string) {
		if call == 1 {
			return http.StatusOK, fullConfigBody("hash-1")
		}
		return http.StatusInternalServerError, ""
	})
	f := newCacheFixture(t, cp.server.URL, pub, time.Minute, 10*time.Minute)

	first, rej := f.cache.Bind(context.Background(), "Bearer "+raw)
	require.Nil(t, rej)
	require.NotNil(t, first.Pipeline)
	require.Equal(t, 1, cp.Calls())

	// Past StaleFor there is no config to fall back on, so a failed refresh
	// is unavailable and remembered for negativeFor.
	f.clock.Advance(11 * time.Minute)
	ten, rej := f.cache.Bind(context.Background(), "Bearer "+raw)
	require.Nil(t, ten)
	require.Same(t, rejectUnavailable, rej)
	require.Equal(t, 2, cp.Calls())

	f.clock.Advance(2 * time.Second)
	ten, rej = f.cache.Bind(context.Background(), "Bearer "+raw)
	require.Nil(t, ten)
	require.Same(t, rejectUnavailable, rej)
	require.Equal(t, 2, cp.Calls())

	// Past negativeFor the proxy tries the control plane again.
	f.clock.Advance(4 * time.Second)
	ten, rej = f.cache.Bind(context.Background(), "Bearer "+raw)
	require.Nil(t, ten)
	require.Same(t, rejectUnavailable, rej)
	require.Equal(t, 3, cp.Calls())
	require.Equal(t, int32(1), f.buildCalls.Load())
}

func TestCacheConcurrentBindsFetchOnce(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKey(t)
	raw := tenantToken(t, priv, "tenant-a", "id-a", testEpoch)
	release := make(chan struct{})
	cp := newConfigControlPlane(t, func(int, configRequest) (int, string) {
		<-release
		return http.StatusOK, fullConfigBody("hash-1")
	})
	f := newCacheFixture(t, cp.server.URL, pub, time.Minute, 10*time.Minute)

	const binders = 20
	start := make(chan struct{})
	tenants := make([]*transform.Tenant, binders)
	rejections := make([]*Rejection, binders)
	var wg sync.WaitGroup
	wg.Add(binders)
	for i := 0; i < binders; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			tenants[i], rejections[i] = f.cache.Bind(context.Background(), "Bearer "+raw)
		}()
	}
	close(start)

	// Hold the single in-flight fetch until every Bind has had a chance to
	// join the token's fetch serialization.
	require.Eventually(t, func() bool { return cp.Calls() == 1 }, time.Second, time.Millisecond)
	close(release)
	wg.Wait()

	require.Equal(t, 1, cp.Calls())
	require.Equal(t, int32(1), f.buildCalls.Load())
	require.NotNil(t, tenants[0])
	for i := 0; i < binders; i++ {
		require.Nil(t, rejections[i])
		require.NotNil(t, tenants[i])
		require.Same(t, tenants[0].Pipeline, tenants[i].Pipeline)
	}
}
