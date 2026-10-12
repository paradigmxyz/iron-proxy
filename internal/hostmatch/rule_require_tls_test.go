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
			rules, err := CompileRules(tc.rules, "test")
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

	rules, err := CompileRules([]RuleConfig{rc}, "test")
	require.NoError(t, err)
	require.True(t, rules[0].RequireTLS, "CompileRules must carry require_tls onto the compiled rule")
}
