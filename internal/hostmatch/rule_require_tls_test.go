package hostmatch

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// httptest.NewRequest sets req.TLS for https:// targets and leaves it nil for
// http:// targets, which is how the proxy sees TLS and plain-HTTP requests.
func TestRequireTLS_Matching(t *testing.T) {
	requireTLS := []RuleConfig{{Host: "api.example.com", RequireTLS: true}}
	noRequireTLS := []RuleConfig{{Host: "api.example.com"}}
	withMethodAndPath := []RuleConfig{{Host: "api.example.com", Methods: []string{"POST"}, Paths: []string{"/token"}, RequireTLS: true}}
	mixed := []RuleConfig{
		{Host: "secure.example.com", RequireTLS: true},
		{Host: "open.example.com"},
	}

	cases := []struct {
		name   string
		rules  []RuleConfig
		method string
		url    string
		want   bool
	}{
		{name: "require_tls matches https", rules: requireTLS, method: "GET", url: "https://api.example.com/v1", want: true},
		{name: "require_tls rejects plain http", rules: requireTLS, method: "GET", url: "http://api.example.com/v1", want: false},
		{name: "default matches https", rules: noRequireTLS, method: "GET", url: "https://api.example.com/", want: true},
		{name: "default matches plain http", rules: noRequireTLS, method: "GET", url: "http://api.example.com/", want: true},
		{name: "with method and path matches https", rules: withMethodAndPath, method: "POST", url: "https://api.example.com/token", want: true},
		{name: "with method and path rejects plain http", rules: withMethodAndPath, method: "POST", url: "http://api.example.com/token", want: false},
		{name: "with method and path rejects wrong method", rules: withMethodAndPath, method: "GET", url: "https://api.example.com/token", want: false},
		{name: "with method and path rejects wrong path", rules: withMethodAndPath, method: "POST", url: "https://api.example.com/other", want: false},
		{name: "per rule: require_tls sibling rejects plain http", rules: mixed, method: "GET", url: "http://secure.example.com/", want: false},
		{name: "per rule: plain sibling still matches plain http", rules: mixed, method: "GET", url: "http://open.example.com/", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := CompileRulesAllowRequireTLS(tc.rules, "test")
			require.NoError(t, err)
			req := httptest.NewRequest(tc.method, tc.url, nil)
			require.Equal(t, tc.want, MatchAnyRule(rules, req))
		})
	}
}

func TestRequireTLS_DefaultsToOff(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{{Host: "api.example.com"}}, "test")
	require.NoError(t, err)
	require.False(t, rules[0].RequireTLS, "require_tls must default to off so existing configs keep working")
}

func TestRequireTLS_DecodesFromYAMLKey(t *testing.T) {
	var rc RuleConfig
	require.NoError(t, yaml.Unmarshal([]byte("host: api.example.com\nrequire_tls: true\n"), &rc))
	require.True(t, rc.RequireTLS)

	rules, err := CompileRulesAllowRequireTLS([]RuleConfig{rc}, "test")
	require.NoError(t, err)
	require.True(t, rules[0].RequireTLS, "require_tls must be carried onto the compiled rule")
}

// require_tls is opt-in per caller. CompileRules (policy rules) rejects it,
// because a plain-HTTP request would stop matching and skip the policy.
// CompileRulesAllowRequireTLS (credential injectors, fail-closed gates)
// accepts it.
func TestRequireTLS_OnlyOptInCallersAcceptIt(t *testing.T) {
	cases := []struct {
		name    string
		compile func([]RuleConfig, string) ([]Rule, error)
		rules   []RuleConfig
		wantErr string
	}{
		{name: "CompileRules rejects require_tls", compile: CompileRules, rules: []RuleConfig{{Host: "a.example.com", RequireTLS: true}}, wantErr: "test: rules[0]: require_tls is not supported here"},
		{name: "CompileRules rejects it on any rule in the list", compile: CompileRules, rules: []RuleConfig{{Host: "a.example.com"}, {Host: "b.example.com", RequireTLS: true}}, wantErr: "test: rules[1]: require_tls is not supported here"},
		{name: "CompileRules accepts rules without it", compile: CompileRules, rules: []RuleConfig{{Host: "a.example.com"}}},
		{name: "CompileRulesAllowRequireTLS accepts it", compile: CompileRulesAllowRequireTLS, rules: []RuleConfig{{Host: "a.example.com", RequireTLS: true}}},
		{name: "CompileRulesAllowRequireTLS still validates rules", compile: CompileRulesAllowRequireTLS, rules: []RuleConfig{{RequireTLS: true}}, wantErr: "one of host or cidr is required"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.compile(tc.rules, "test")
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
