package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
	_ "github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// A credential-free smoke test for an agent's OpenAI-compatible request path.
// All listeners are ephemeral loopback listeners; no host trust or agent config
// is changed. The env backend stands in for a successfully exported secret.
func TestTunnel_AgentSecretBoundary(t *testing.T) {
	const proxyToken = "synthetic-agent-placeholder"
	const upstreamSecret = "synthetic-provider-secret"
	t.Setenv("IRON_AGENT_SMOKE_SECRET", upstreamSecret)
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+upstreamSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// The mock provider never echoes its credential to the agent.
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"synthetic agent response"}}]}`) // Client disconnects are irrelevant to this mock.
	}))
	defer upstream.Close()
	allowed, err := allowlist.New([]string{"127.0.0.1"}, nil)
	require.NoError(t, err)
	factory, err := transform.Lookup("secrets")
	require.NoError(t, err)
	var cfg yaml.Node
	require.NoError(t, cfg.Encode(map[string]any{"secrets": []any{map[string]any{
		"source":  map[string]any{"type": "env", "var": "IRON_AGENT_SMOKE_SECRET"},
		"replace": map[string]any{"proxy_value": proxyToken, "match_headers": []string{"Authorization"}, "require": true},
		"rules":   []any{map[string]any{"host": "127.0.0.1"}},
	}}}))
	secretTransform, err := factory(cfg, testLogger())
	require.NoError(t, err)
	_, addr, _ := startTunnelProxy(t, []transform.Transformer{allowed, secretTransform})
	proxyURL, err := url.Parse("http://" + addr)
	require.NoError(t, err)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	cases := []struct {
		name, target, token string
		status              int
	}{
		{"agent placeholder replaced", upstream.URL + "/v1/chat/completions", proxyToken, http.StatusOK},
		{"missing required placeholder", upstream.URL + "/v1/chat/completions", "wrong-placeholder", http.StatusForbidden},
		{"unapproved host", "http://blocked.invalid/v1/chat/completions", proxyToken, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), "POST", tc.target, strings.NewReader(`{"model":"synthetic","messages":[{"role":"user","content":"hello"}]}`))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, tc.status, resp.StatusCode)
			require.NotContains(t, string(body), upstreamSecret)
			if tc.status == http.StatusOK {
				require.Contains(t, string(body), "synthetic agent response")
			}
		})
	}
	require.Equal(t, int32(1), upstreamCalls.Load(), "rejected requests must not reach the provider")
}
