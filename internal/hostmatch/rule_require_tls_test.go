package hostmatch

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// httptest.NewRequest sets req.TLS for https:// targets and leaves it nil for
// http:// targets, which is how the proxy sees TLS and plain-HTTP requests.

func TestRequireTLS_MatchesOnlyTLSRequests(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "api.example.com", RequireTLS: true},
	}, "test")
	require.NoError(t, err)
	require.True(t, rules[0].RequireTLS)

	tlsReq := httptest.NewRequest("GET", "https://api.example.com/v1", nil)
	require.NotNil(t, tlsReq.TLS)
	require.True(t, MatchAnyRule(rules, tlsReq))

	plainReq := httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	require.Nil(t, plainReq.TLS)
	require.False(t, MatchAnyRule(rules, plainReq), "require_tls rule must not match plain HTTP")
}

func TestRequireTLS_DefaultMatchesBothSchemes(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{{Host: "api.example.com"}}, "test")
	require.NoError(t, err)
	require.False(t, rules[0].RequireTLS, "require_tls must default to off so existing configs keep working")

	require.True(t, MatchAnyRule(rules, httptest.NewRequest("GET", "https://api.example.com/", nil)))
	require.True(t, MatchAnyRule(rules, httptest.NewRequest("GET", "http://api.example.com/", nil)))
}

func TestRequireTLS_CombinesWithMethodsAndPaths(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "api.example.com", Methods: []string{"POST"}, Paths: []string{"/token"}, RequireTLS: true},
	}, "test")
	require.NoError(t, err)

	require.True(t, MatchAnyRule(rules, httptest.NewRequest("POST", "https://api.example.com/token", nil)))
	require.False(t, MatchAnyRule(rules, httptest.NewRequest("POST", "http://api.example.com/token", nil)), "plain HTTP")
	require.False(t, MatchAnyRule(rules, httptest.NewRequest("GET", "https://api.example.com/token", nil)), "wrong method")
	require.False(t, MatchAnyRule(rules, httptest.NewRequest("POST", "https://api.example.com/other", nil)), "wrong path")
}

// One rule requiring TLS must not stop a sibling rule without it from
// matching plain HTTP: require_tls is per rule.
func TestRequireTLS_IsPerRule(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "secure.example.com", RequireTLS: true},
		{Host: "open.example.com"},
	}, "test")
	require.NoError(t, err)

	require.False(t, MatchAnyRule(rules, httptest.NewRequest("GET", "http://secure.example.com/", nil)))
	require.True(t, MatchAnyRule(rules, httptest.NewRequest("GET", "http://open.example.com/", nil)))
}

func TestRequireTLS_DecodesFromYAMLKey(t *testing.T) {
	var rc RuleConfig
	require.NoError(t, yaml.Unmarshal([]byte("host: api.example.com\nrequire_tls: true\n"), &rc))
	require.True(t, rc.RequireTLS)
}
