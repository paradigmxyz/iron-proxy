package headerallowlist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func runRequest(t *testing.T, h *HeaderAllowlist, req *http.Request) (*transform.TransformContext, *transform.TransformResult) {
	t.Helper()
	tctx := &transform.TransformContext{}
	res, err := h.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	return tctx, res
}

func headerNames(req *http.Request) []string {
	names := make([]string, 0, len(req.Header))
	for k := range req.Header {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func TestHeaderAllowlist_StripsDisallowed(t *testing.T) {
	h, err := newFromConfig(config{Headers: []string{"Authorization", "Content-Type"}})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "http://api.example.com/", nil)
	req.Header.Set("Authorization", "Bearer x")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "session=abc")
	req.Header.Set("X-Sneaky", "1")

	tctx, _ := runRequest(t, h, req)

	require.Equal(t, []string{"Authorization", "Content-Type"}, headerNames(req))

	stripped := tctx.DrainAnnotations()["stripped_headers"].([]string)
	sort.Strings(stripped)
	require.Equal(t, []string{"Cookie", "X-Sneaky"}, stripped)
}

func TestHeaderAllowlist_CaseInsensitiveMatch(t *testing.T) {
	h, err := newFromConfig(config{Headers: []string{"x-request-id"}})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("X-Request-Id", "abc")
	req.Header.Set("x-other", "1")

	runRequest(t, h, req)
	require.Equal(t, []string{"X-Request-Id"}, headerNames(req))
}

func TestHeaderAllowlist_NonCanonicalMapKeys(t *testing.T) {
	h, err := newFromConfig(config{Headers: []string{"Accept", "x-keep"}})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Accept", "application/json")
	// Keys written with preserved wire casing, as internal/headers does.
	req.Header["x-api-key"] = []string{"secret"}
	req.Header["X-API-TOKEN"] = []string{"secret"}
	req.Header["x-keep"] = []string{"1"}

	tctx, _ := runRequest(t, h, req)

	require.Equal(t, []string{"Accept", "x-keep"}, headerNames(req))

	stripped := tctx.DrainAnnotations()["stripped_headers"].([]string)
	sort.Strings(stripped)
	require.Equal(t, []string{"X-API-TOKEN", "x-api-key"}, stripped)
}

func TestHeaderAllowlist_RegexEntry(t *testing.T) {
	h, err := newFromConfig(config{Headers: []string{"/^X-Trace-.*$/"}})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("X-Trace-Id", "1")
	req.Header.Set("X-Trace-Parent", "2")
	req.Header.Set("X-Other", "3")

	runRequest(t, h, req)
	require.Equal(t, []string{"X-Trace-Id", "X-Trace-Parent"}, headerNames(req))
}

func TestHeaderAllowlist_AllAllowed_NoAnnotation(t *testing.T) {
	h, err := newFromConfig(config{Headers: []string{"Authorization"}})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer x")

	tctx, _ := runRequest(t, h, req)
	require.Equal(t, []string{"Authorization"}, headerNames(req))
	require.Nil(t, tctx.DrainAnnotations())
}

func TestHeaderAllowlist_RulesScopeMatching(t *testing.T) {
	h, err := newFromConfig(config{
		Headers: []string{"Authorization"},
		Rules: []hostmatch.RuleConfig{
			{Host: "api.example.com"},
		},
	})
	require.NoError(t, err)

	// In-scope: stripping happens.
	req1 := httptest.NewRequest("GET", "http://api.example.com/", nil)
	req1.Host = "api.example.com"
	req1.Header.Set("Authorization", "Bearer x")
	req1.Header.Set("X-Other", "1")
	runRequest(t, h, req1)
	require.Equal(t, []string{"Authorization"}, headerNames(req1))

	// Out-of-scope: untouched.
	req2 := httptest.NewRequest("GET", "http://other.example.com/", nil)
	req2.Host = "other.example.com"
	req2.Header.Set("Authorization", "Bearer x")
	req2.Header.Set("X-Other", "1")
	runRequest(t, h, req2)
	require.Equal(t, []string{"Authorization", "X-Other"}, headerNames(req2))
}

func TestHeaderAllowlist_NoRulesAppliesToAll(t *testing.T) {
	h, err := newFromConfig(config{Headers: []string{"Content-Type"}})
	require.NoError(t, err)

	for _, host := range []string{"a.example.com", "b.example.com"} {
		req := httptest.NewRequest("GET", "http://"+host+"/", nil)
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Drop", "1")
		runRequest(t, h, req)
		require.Equal(t, []string{"Content-Type"}, headerNames(req))
	}
}

func TestHeaderAllowlist_ResponseIsNoop(t *testing.T) {
	h, err := newFromConfig(config{Headers: []string{"Authorization"}})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}}
	resp.Header.Set("X-Server", "nginx")

	res, err := h.TransformResponse(context.Background(), &transform.TransformContext{}, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	// Response headers untouched.
	require.Equal(t, "nginx", resp.Header.Get("X-Server"))
}

func TestHeaderAllowlist_Name(t *testing.T) {
	h, err := newFromConfig(config{Headers: []string{"Authorization"}})
	require.NoError(t, err)
	require.Equal(t, "header_allowlist", h.Name())
}

func TestHeaderAllowlist_RequiresHeaders(t *testing.T) {
	_, err := newFromConfig(config{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one header is required")
}

func TestHeaderAllowlist_InvalidRegex(t *testing.T) {
	_, err := newFromConfig(config{Headers: []string{"/[unterminated/"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid headers regex")
}

func TestHeaderAllowlist_InvalidRule(t *testing.T) {
	_, err := newFromConfig(config{
		Headers: []string{"Authorization"},
		Rules:   []hostmatch.RuleConfig{{Host: "a.com", CIDR: "10.0.0.0/8"}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}
