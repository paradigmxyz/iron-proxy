package allowlist

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func result(t *testing.T, a *Allowlist, host string) *transform.TransformResult {
	t.Helper()
	req := httptest.NewRequest("GET", "http://"+host+"/", nil)
	req.Host = host
	res, err := a.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	return res
}

func resultWithMethodAndPath(t *testing.T, a *Allowlist, host, method, path string) *transform.TransformResult {
	t.Helper()
	req := httptest.NewRequest(method, "http://"+host+path, nil)
	req.Host = host
	res, err := a.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	return res
}

// --- Existing tests (backwards compat via New) ---

func TestAllowlist_ExactDomainMatch(t *testing.T) {
	a, err := New([]string{"api.openai.com"}, nil)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.openai.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "evil.com").Action)
}

func TestAllowlist_WildcardDomain(t *testing.T) {
	a, err := New([]string{"*.anthropic.com"}, nil)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.anthropic.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "docs.api.anthropic.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "anthropic.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "notanthropic.com").Action)
}

func TestAllowlist_HostWithPort(t *testing.T) {
	a, err := New([]string{"api.openai.com"}, nil)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.openai.com:443").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "evil.com:443").Action)
}

func TestAllowlist_CIDRMatchesLiteralIP(t *testing.T) {
	a, err := New(nil, []string{"10.0.0.0/8"})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "10.0.1.5").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "10.0.1.5:8080").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "8.8.8.8").Action)
}

func TestAllowlist_CIDRDoesNotResolveHostnames(t *testing.T) {
	// Hostnames are never resolved to check against CIDRs — only literal IPs match.
	a, err := New(nil, []string{"10.0.0.0/8"})
	require.NoError(t, err)

	require.Equal(t, transform.ActionReject, result(t, a, "internal.service").Action)
}

func TestAllowlist_MultipleCIDRs(t *testing.T) {
	a, err := New(nil, []string{"10.0.0.0/8", "172.16.0.0/12"})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "10.0.0.1").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "172.16.0.1").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "8.8.8.8").Action)
}

func TestAllowlist_DomainAndCIDRTogether(t *testing.T) {
	a, err := New([]string{"allowed.com"}, []string{"10.0.0.0/8"})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "allowed.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "10.0.1.5").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "evil.com").Action)
}

func TestAllowlist_EmptyAllowlistDeniesAll(t *testing.T) {
	a, err := New(nil, nil)
	require.NoError(t, err)

	require.Equal(t, transform.ActionReject, result(t, a, "anything.com").Action)
}

func TestAllowlist_MultipleDomains(t *testing.T) {
	a, err := New([]string{"a.com", "b.com", "*.c.com"}, nil)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "a.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "b.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "sub.c.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "d.com").Action)
}

func TestAllowlist_InvalidCIDR(t *testing.T) {
	_, err := New(nil, []string{"not-a-cidr"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "parsing CIDR")
}

func TestAllowlist_ResponseIsNoop(t *testing.T) {
	a, err := New(nil, nil)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{StatusCode: http.StatusOK}
	res, err := a.TransformResponse(context.Background(), &transform.TransformContext{}, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestAllowlist_Name(t *testing.T) {
	a, err := New(nil, nil)
	require.NoError(t, err)
	require.Equal(t, "allowlist", a.Name())
}

// --- Method matching tests ---

func TestAllowlist_MethodAllowed(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:    "api.openai.com",
			Methods: []string{"GET", "POST"},
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "DELETE", "/").Action)
}

func TestAllowlist_MethodsCaseInsensitive(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:    "api.openai.com",
			Methods: []string{"post"},
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/").Action)
}

func TestAllowlist_NoMethodsAllowsAll(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host: "api.openai.com",
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "DELETE", "/").Action)
}

// --- Path matching tests ---

func TestAllowlist_PathGlob(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:  "api.openai.com",
			Paths: []string{"/v1/*"},
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/models").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/chat/completions").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v2/models").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/").Action)
}

func TestAllowlist_PathExact(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:  "api.openai.com",
			Paths: []string{"/health"},
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/health").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/health/deep").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/other").Action)
}

func TestAllowlist_NoPathsAllowsAll(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host: "api.openai.com",
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/anything").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/models").Action)
}

func TestAllowlist_MultiplePaths(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:  "api.openai.com",
			Paths: []string{"/v1/chat", "/v1/models"},
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/chat").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/models").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/other").Action)
}

// --- Combined tests ---

func TestAllowlist_HostMethodPathCombined(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:    "api.openai.com",
			Methods: []string{"POST"},
			Paths:   []string{"/v1/*"},
		}},
	})
	require.NoError(t, err)

	// All three match
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/v1/chat").Action)
	// Wrong method
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/chat").Action)
	// Wrong path
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/v2/chat").Action)
	// Wrong host
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "evil.com", "POST", "/v1/chat").Action)
}

func TestAllowlist_MultiRuleSecondMatches(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{
			{Host: "api.openai.com", Methods: []string{"POST"}},
			{Host: "api.anthropic.com", Methods: []string{"GET"}},
		},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.anthropic.com", "GET", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.anthropic.com", "POST", "/").Action)
}

func TestAllowlist_FlatDomainsAndRulesMixed(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Domains: []string{"open.com"},
		Rules: []hostmatch.RuleConfig{{
			Host:    "restricted.com",
			Methods: []string{"GET"},
		}},
	})
	require.NoError(t, err)

	// Flat domain: all methods allowed
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "open.com", "DELETE", "/anything").Action)
	// Rule: only GET
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "restricted.com", "GET", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "restricted.com", "POST", "/").Action)
}

func TestAllowlist_RuleWithCIDR(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			CIDR:    "10.0.0.0/8",
			Methods: []string{"GET"},
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "10.0.1.5", "GET", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "10.0.1.5", "POST", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "internal.service", "GET", "/").Action)
}

// --- Warn mode tests ---

func TestAllowlist_WarnModeAllowsBlockedRequests(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Domains: []string{"api.openai.com"},
		Warn:    true,
	})
	require.NoError(t, err)

	// Allowed request: no annotation
	tctx := &transform.TransformContext{}
	req := httptest.NewRequest("GET", "http://api.openai.com/", nil)
	req.Host = "api.openai.com"
	res, err := a.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Nil(t, tctx.DrainAnnotations())

	// Blocked request in warn mode: continues with annotation
	tctx2 := &transform.TransformContext{}
	req2 := httptest.NewRequest("GET", "http://evil.com/", nil)
	req2.Host = "evil.com"
	res2, err := a.TransformRequest(context.Background(), tctx2, req2)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res2.Action)
	annotations := tctx2.DrainAnnotations()
	require.Equal(t, "warn", annotations["action"])
}

func TestAllowlist_WarnFalseStillRejects(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Domains: []string{"api.openai.com"},
		Warn:    false,
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionReject, result(t, a, "evil.com").Action)
}

func TestAllowlist_WarnModeWithRules(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:    "api.openai.com",
			Methods: []string{"GET"},
		}},
		Warn: true,
	})
	require.NoError(t, err)

	// Wrong method in warn mode: continues with annotation
	tctx := &transform.TransformContext{}
	req := httptest.NewRequest("POST", "http://api.openai.com/", nil)
	req.Host = "api.openai.com"
	res, err := a.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	annotations := tctx.DrainAnnotations()
	require.Equal(t, "warn", annotations["action"])

	// Wrong host in warn mode: continues with annotation
	tctx2 := &transform.TransformContext{}
	req2 := httptest.NewRequest("GET", "http://evil.com/", nil)
	req2.Host = "evil.com"
	res2, err := a.TransformRequest(context.Background(), tctx2, req2)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res2.Action)
	annotations2 := tctx2.DrainAnnotations()
	require.Equal(t, "warn", annotations2["action"])
}

// --- Validation tests ---

func TestAllowlist_RuleBothHostAndCIDR(t *testing.T) {
	_, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{Host: "a.com", CIDR: "10.0.0.0/8"}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}

func TestAllowlist_RuleNeitherHostNorCIDR(t *testing.T) {
	_, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{Methods: []string{"GET"}}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "one of host or cidr is required")
}

func TestAllowlist_RuleInvalidPath(t *testing.T) {
	_, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{Host: "a.com", Paths: []string{"no-leading-slash"}}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "must start with /")
}

// --- matchPath unit tests ---

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/v1/*", "/v1/models", true},
		{"/v1/*", "/v1/chat/completions", true},
		{"/v1/*", "/v1", true},
		{"/v1/*", "/v2/models", false},
		{"/v1/*", "/", false},
		{"/health", "/health", true},
		{"/health", "/health/deep", false},
		{"/health", "/other", false},
		{"/*", "/anything", true},
		{"/*", "/", true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.pattern, tt.path), func(t *testing.T) {
			require.Equal(t, tt.want, hostmatch.MatchPath(tt.pattern, tt.path))
		})
	}
}

// --- Tunnel preflight ---

// preflightResult runs the synthetic CONNECT request that the proxy builds in
// tunnelTransformCheck before a tunnel is established.
func preflightResult(t *testing.T, a *Allowlist, target string) *transform.TransformResult {
	t.Helper()
	req := &http.Request{Method: http.MethodConnect, Host: target, URL: &url.URL{Host: target}}
	res, err := a.TransformRequest(context.Background(), &transform.TransformContext{TunnelPreflight: true}, req)
	require.NoError(t, err)
	return res
}

func TestAllowlist_TunnelPreflightMatchesHostOnly(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{
			{Host: "api.openai.com", Methods: []string{"POST"}, Paths: []string{"/v1/*"}},
			{CIDR: "10.0.0.0/8", Methods: []string{"GET"}},
		},
	})
	require.NoError(t, err)

	cases := []struct {
		name   string
		target string
		want   transform.TransformAction
	}{
		{"host rule with methods and paths", "api.openai.com:443", transform.ActionContinue},
		{"cidr rule with methods", "10.1.2.3:443", transform.ActionContinue},
		{"unlisted host", "evil.com:443", transform.ActionReject},
		{"unlisted ip", "192.168.1.1:443", transform.ActionReject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, preflightResult(t, a, tc.target).Action)
		})
	}
}

func TestAllowlist_ConnectOutsidePreflightKeepsMethodRules(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{Host: "api.openai.com", Methods: []string{"GET"}}},
	})
	require.NoError(t, err)

	// A real CONNECT request (e.g. sent inside an established tunnel) is not
	// the preflight and must still match the method restriction.
	req := &http.Request{Method: http.MethodConnect, Host: "api.openai.com:443", URL: &url.URL{Host: "api.openai.com:443"}}
	res, err := a.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
}
