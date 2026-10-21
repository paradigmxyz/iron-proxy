package secrets

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func selectionEntry(source, token, group, header string) secretEntry {
	return secretEntry{
		Source:         envSource(source),
		SelectionGroup: group,
		Replace: &replaceConfig{
			ProxyValue: token, MatchHeaders: []string{header}, Require: true,
		},
		Rules: []hostmatch.RuleConfig{{Host: "api.openai.com", Methods: []string{"POST"}, Paths: []string{"/v1/responses"}}},
	}
}

func TestSecrets_AlternativeAccounts(t *testing.T) {
	cases := []struct {
		name   string
		header http.Header
		want   string
	}{
		{name: "raw first account", header: http.Header{"Authorization": {"account-a"}}, want: "secret-a"},
		{name: "bearer first account", header: http.Header{"Authorization": {"Bearer account-a"}}, want: "Bearer secret-a"},
		{name: "second account", header: http.Header{"Authorization": {"Bearer account-b"}}, want: "Bearer secret-b"},
		{name: "case insensitive bearer", header: http.Header{"Authorization": {"bearer account-a"}}, want: "bearer secret-a"},
		{name: "missing"},
		{name: "unknown marker", header: http.Header{"Authorization": {"Bearer account-c"}}},
		{name: "plain credential", header: http.Header{"Authorization": {"Bearer upstream-credential"}}},
		{name: "marker prefix", header: http.Header{"Authorization": {"Bearer prefix-account-a"}}},
		{name: "marker suffix", header: http.Header{"Authorization": {"Bearer account-a-suffix"}}},
		{name: "basic auth", header: http.Header{"Authorization": {"Basic dXNlcjphY2NvdW50LWE="}}},
		{name: "concatenated markers", header: http.Header{"Authorization": {"Bearer account-a account-b"}}},
		{name: "multiple accounts", header: http.Header{"Authorization": {"Bearer account-a", "Bearer account-b"}}},
		{name: "selected and plain credential", header: http.Header{"Authorization": {"Bearer account-a", "Bearer upstream-credential"}}},
		{name: "selected and unknown marker", header: http.Header{"Authorization": {"Bearer account-a", "Bearer account-c"}}},
		{name: "unauthorized header", header: http.Header{"X-Api-Key": {"account-a"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			builder := &fakeBuilder{secrets: map[string]string{"A": "secret-a", "B": "secret-b"}}
			s, err := newFromConfig(secretsConfig{Secrets: []secretEntry{
				selectionEntry("A", "account-a", "provider-account", "Authorization"),
				selectionEntry("B", "account-b", "provider-account", "Authorization"),
			}}, sourceBuilderRegistry{"env": builder})
			require.NoError(t, err)
			req := openaiReq("POST", "/v1/responses")
			req.Header = tc.header.Clone()
			before := req.Header.Clone()
			tctx := &transform.TransformContext{}
			result, err := s.TransformRequest(context.Background(), tctx, req)
			require.NoError(t, err)
			if tc.want == "" {
				require.Equal(t, transform.ActionReject, result.Action)
				require.Equal(t, before, req.Header)
				require.Empty(t, builder.fetchCalls)
				require.Equal(t, map[string]any{"rejected": "provider-account", "reject_reason": "credential_selection"}, tctx.DrainAnnotations())
				return
			}
			require.Equal(t, transform.ActionContinue, result.Action)
			require.Equal(t, tc.want, req.Header.Get("Authorization"))
			require.Len(t, builder.fetchCalls, 1)
		})
	}
}

func TestSecrets_AlternativeSelectionPrecedesMutation(t *testing.T) {
	cases := []struct {
		name    string
		headers http.Header
	}{
		{name: "missing other group", headers: http.Header{"Authorization": {"Bearer account-a"}, "X-Independent": {"independent"}}},
		{name: "ambiguous other group", headers: http.Header{"Authorization": {"Bearer account-a"}, "X-Independent": {"independent"}, "X-Token": {"token-c", "token-d"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			builder := &fakeBuilder{secrets: map[string]string{"A": "secret-a", "B": "secret-b", "C": "secret-c", "D": "secret-d"}}
			independent := selectionEntry("A", "independent", "", "X-Independent")
			s, err := newFromConfig(secretsConfig{Secrets: []secretEntry{
				independent,
				selectionEntry("A", "account-a", "provider-account", "Authorization"),
				selectionEntry("B", "account-b", "provider-account", "Authorization"),
				selectionEntry("C", "token-c", "second-credential", "X-Token"),
				selectionEntry("D", "token-d", "second-credential", "X-Token"),
			}}, sourceBuilderRegistry{"env": builder})
			require.NoError(t, err)
			req := openaiReq("POST", "/v1/responses")
			req.Header = tc.headers.Clone()
			result, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
			require.NoError(t, err)
			require.Equal(t, transform.ActionReject, result.Action)
			require.Equal(t, tc.headers, req.Header)
			require.Empty(t, builder.fetchCalls)
		})
	}
}

func TestSecrets_AlternativeSelectionIsNotChangedByReplacement(t *testing.T) {
	builder := &fakeBuilder{secrets: map[string]string{"A": "account-b", "B": "secret-b"}}
	s, err := newFromConfig(secretsConfig{Secrets: []secretEntry{
		selectionEntry("A", "account-a", "provider-account", "Authorization"),
		selectionEntry("B", "account-b", "provider-account", "Authorization"),
	}}, sourceBuilderRegistry{"env": builder})
	require.NoError(t, err)
	req := openaiReq("POST", "/v1/responses")
	req.Header.Set("Authorization", "Bearer account-a")
	doTransform(t, s, req)
	require.Equal(t, "Bearer account-b", req.Header.Get("Authorization"))
	require.Equal(t, map[string]int{"A": 1}, builder.fetchCalls)
}

func TestSecrets_AlternativeSelectionUsesExactMarkers(t *testing.T) {
	s := makeSecrets(t, []secretEntry{
		selectionEntry("OPENAI_API_KEY", "account", "provider-account", "Authorization"),
		selectionEntry("INTERNAL_TOKEN", "account-b", "provider-account", "Authorization"),
	})
	req := openaiReq("POST", "/v1/responses")
	req.Header.Set("Authorization", "Bearer account-b")
	doTransform(t, s, req)
	require.Equal(t, "Bearer real-internal-token", req.Header.Get("Authorization"))
}

func TestSecrets_AlternativeSelectionPreservesBearerScheme(t *testing.T) {
	s := makeSecrets(t, []secretEntry{
		selectionEntry("OPENAI_API_KEY", "a", "provider-account", "Authorization"),
	})
	req := openaiReq("POST", "/v1/responses")
	req.Header.Set("Authorization", "Bearer a")
	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_AlternativeSelectionRejectsSharedHeaderWriters(t *testing.T) {
	cases := []struct {
		name string
		edit func(*secretEntry)
	}{
		{name: "required replacement", edit: func(e *secretEntry) {}},
		{name: "optional replacement", edit: func(e *secretEntry) { e.Replace.Require = false }},
		{name: "all headers", edit: func(e *secretEntry) { e.Replace.MatchHeaders = nil }},
		{name: "regex header", edit: func(e *secretEntry) { e.Replace.MatchHeaders = []string{"/^authorization$/"} }},
		{name: "case alias", edit: func(e *secretEntry) { e.Replace.MatchHeaders = []string{"authorization"} }},
		{name: "another group", edit: func(e *secretEntry) {
			e.SelectionGroup = "another-group"
			e.Replace.ProxyValue = "account-a"
		}},
		{name: "injection", edit: func(e *secretEntry) {
			e.Replace = nil
			e.Inject = &injectConfig{Header: "Authorization", Require: true}
		}},
	}
	for _, tc := range cases {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%t", tc.name, reverse), func(t *testing.T) {
				builder := &fakeBuilder{secrets: map[string]string{"A": "bridge-token", "B": "secret-b"}}
				other := selectionEntry("B", "bridge-token", "", "Authorization")
				tc.edit(&other)
				entries := []secretEntry{selectionEntry("A", "account-a", "provider-account", "Authorization"), other}
				if reverse {
					entries[0], entries[1] = entries[1], entries[0]
				}
				s, err := newFromConfig(secretsConfig{Secrets: entries}, sourceBuilderRegistry{"env": builder})
				require.NoError(t, err)
				req := openaiReq("POST", "/v1/responses")
				req.Header.Set("Authorization", "Bearer account-a")
				before := req.Header.Clone()
				result, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
				require.NoError(t, err)
				require.Equal(t, transform.ActionReject, result.Action)
				require.Equal(t, before, req.Header)
				require.Empty(t, builder.fetchCalls)
			})
		}
	}
}

func TestSecrets_AlternativeSelectionPreservesIndependentRequirements(t *testing.T) {
	cases := []struct {
		name        string
		independent string
		want        transform.TransformAction
	}{
		{name: "missing independent credential", want: transform.ActionReject},
		{name: "both credentials", independent: "internal-token", want: transform.ActionContinue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSecrets(t, []secretEntry{
				selectionEntry("OPENAI_API_KEY", "account-a", "provider-account", "Authorization"),
				selectionEntry("MISSING_ACCOUNT", "account-b", "provider-account", "Authorization"),
				selectionEntry("INTERNAL_TOKEN", "internal-token", "", "X-Internal"),
			})
			req := openaiReq("POST", "/v1/responses")
			req.Header.Set("Authorization", "Bearer account-a")
			if tc.independent != "" {
				req.Header.Set("X-Internal", tc.independent)
			}
			result, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
			require.NoError(t, err)
			require.Equal(t, tc.want, result.Action)
			if tc.want == transform.ActionContinue {
				require.Equal(t, "real-internal-token", req.Header.Get("X-Internal"))
			}
		})
	}
}

func TestSecrets_AlternativeSelectionRejectsInjectionIntoAbsentGroupedHeader(t *testing.T) {
	builder := &fakeBuilder{secrets: map[string]string{"A": "secret-a", "B": "secret-b"}}
	other := selectionEntry("B", "unused", "", "Authorization")
	other.Replace = nil
	other.Inject = &injectConfig{Header: "X-Alternate", Require: true}
	s, err := newFromConfig(secretsConfig{Secrets: []secretEntry{
		selectionEntry("A", "account-a", "provider-account", "/^X-/"),
		other,
	}}, sourceBuilderRegistry{"env": builder})
	require.NoError(t, err)
	req := openaiReq("POST", "/v1/responses")
	req.Header.Set("X-Key", "account-a")
	before := req.Header.Clone()
	result, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, result.Action)
	require.Equal(t, before, req.Header)
	require.Empty(t, builder.fetchCalls)
}

func TestSecrets_AlternativeSelectionPreservesQueryOnlyInjection(t *testing.T) {
	other := selectionEntry("INTERNAL_TOKEN", "unused", "", "Authorization")
	other.Replace = nil
	other.Inject = &injectConfig{QueryParam: "api_key", Require: true}
	s := makeSecrets(t, []secretEntry{
		selectionEntry("OPENAI_API_KEY", "account-a", "provider-account", "/.*/"),
		other,
	})
	req := openaiReq("POST", "/v1/responses")
	req.Header.Set("Authorization", "Bearer account-a")
	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	require.Equal(t, "real-internal-token", req.URL.Query().Get("api_key"))
}

func TestSecrets_AlternativeSelectionIgnoresUnmatchedRules(t *testing.T) {
	cases := []struct{ name, method, path, host string }{
		{name: "host", method: "POST", path: "/v1/responses", host: "other.example"},
		{name: "method", method: "GET", path: "/v1/responses", host: "api.openai.com"},
		{name: "path", method: "POST", path: "/v1/other", host: "api.openai.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSecrets(t, []secretEntry{selectionEntry("MISSING_ACCOUNT", "account-a", "provider-account", "Authorization")})
			req := openaiReq(tc.method, tc.path)
			req.Host = tc.host
			req.Header.Set("Authorization", "Bearer upstream-credential")
			doTransform(t, s, req)
			require.Equal(t, "Bearer upstream-credential", req.Header.Get("Authorization"))
		})
	}
}

func TestSecrets_AlternativeSelectionIndependentGroups(t *testing.T) {
	s := makeSecrets(t, []secretEntry{
		selectionEntry("OPENAI_API_KEY", "account-a", "provider-account", "Authorization"),
		selectionEntry("MISSING_ACCOUNT", "account-b", "provider-account", "Authorization"),
		selectionEntry("INTERNAL_TOKEN", "internal-token", "internal-account", "X-Internal"),
		selectionEntry("MISSING_INTERNAL", "other-token", "internal-account", "X-Internal"),
	})
	req := openaiReq("POST", "/v1/responses")
	req.Header.Set("Authorization", "Bearer account-a")
	req.Header.Set("X-Internal", "internal-token")
	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	require.Equal(t, "real-internal-token", req.Header.Get("X-Internal"))
}

func TestSecrets_AlternativeSelectionUnavailableAccount(t *testing.T) {
	s := makeSecrets(t, []secretEntry{
		selectionEntry("OPENAI_API_KEY", "account-a", "provider-account", "Authorization"),
		selectionEntry("MISSING_ACCOUNT", "account-b", "provider-account", "Authorization"),
	})
	req := openaiReq("POST", "/v1/responses")
	req.Header.Set("Authorization", "Bearer account-b")
	tctx := &transform.TransformContext{}
	result, err := s.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, result.Action)
	require.Equal(t, "Bearer account-b", req.Header.Get("Authorization"))
	require.Equal(t, "secret_unavailable", tctx.DrainAnnotations()["reject_reason"])
}

func TestSecrets_AlternativeSelectionControlsAllMatchingHeaders(t *testing.T) {
	cases := []struct {
		name, second string
		want         transform.TransformAction
	}{
		{name: "only chosen header", want: transform.ActionContinue},
		{name: "unselected account header", second: "account-b", want: transform.ActionReject},
		{name: "chosen marker in unselected header", second: "account-a", want: transform.ActionReject},
		{name: "plain second header", second: "raw-key", want: transform.ActionReject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSecrets(t, []secretEntry{
				selectionEntry("OPENAI_API_KEY", "account-a", "provider-account", "Authorization"),
				selectionEntry("ANTHROPIC_API_KEY", "account-b", "provider-account", "X-Api-Key"),
			})
			req := openaiReq("POST", "/v1/responses")
			req.Header.Set("Authorization", "Bearer account-a")
			if tc.second != "" {
				req.Header.Set("X-Api-Key", tc.second)
			}
			result, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
			require.NoError(t, err)
			require.Equal(t, tc.want, result.Action)
		})
	}
}

func TestSecrets_AlternativeSelectionRequiresHeaderReplacement(t *testing.T) {
	cases := []struct {
		name string
		edit func(*secretEntry)
	}{
		{name: "optional replacement", edit: func(e *secretEntry) { e.Replace.Require = false }},
		{name: "all headers", edit: func(e *secretEntry) { e.Replace.MatchHeaders = nil }},
		{name: "body", edit: func(e *secretEntry) { e.Replace.MatchBody = true }},
		{name: "path", edit: func(e *secretEntry) { e.Replace.MatchPath = true }},
		{name: "query", edit: func(e *secretEntry) { e.Replace.MatchQuery = true }},
		{name: "injection", edit: func(e *secretEntry) {
			e.Replace = nil
			e.Inject = &injectConfig{Header: "Authorization", Require: true}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := selectionEntry("OPENAI_API_KEY", "account-a", "provider-account", "Authorization")
			tc.edit(&entry)
			_, err := newFromConfig(secretsConfig{Secrets: []secretEntry{entry}}, testRegistry())
			require.ErrorContains(t, err, "selection_group requires mandatory header-only replacement")
		})
	}
}

func TestSecrets_AlternativeSelectionJSONConfig(t *testing.T) {
	var cfg yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(`{"secrets":[
		{"source":{"type":"control_plane","value":"secret-a"},"selection_group":"provider-account","replace":{"proxy_value":"account-a","match_headers":["Authorization"],"require":true},"rules":[{"host":"api.openai.com"}]},
		{"source":{"type":"control_plane","value":"secret-b"},"selection_group":"provider-account","replace":{"proxy_value":"account-b","match_headers":["Authorization"],"require":true},"rules":[{"host":"api.openai.com"}]}
	]}`), &cfg))
	s, err := factory(cfg, nil)
	require.NoError(t, err)
	req := openaiReq("POST", "/v1/responses")
	req.Header.Set("Authorization", "Bearer account-b")
	result, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	require.Equal(t, "Bearer secret-b", req.Header.Get("Authorization"))
}
