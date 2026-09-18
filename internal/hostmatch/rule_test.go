package hostmatch

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompileRules_WildcardMethodMatchesAll(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "example.com", Methods: []string{"*"}},
	}, "test")
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.Nil(t, rules[0].Methods, "wildcard method should result in nil Methods (match all)")

	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"} {
		require.True(t, rules[0].Matches("example.com", "80", method, "/"), "method %s should match", method)
	}
}

func TestCompileRules_ExplicitMethodsFiltered(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "example.com", Methods: []string{"GET", "post"}},
	}, "test")
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.NotNil(t, rules[0].Methods)

	require.True(t, rules[0].Matches("example.com", "80", "GET", "/"))
	require.True(t, rules[0].Matches("example.com", "80", "POST", "/"))
	require.False(t, rules[0].Matches("example.com", "80", "DELETE", "/"))
}

func TestCompileRules_NoMethodsMatchesAll(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "example.com"},
	}, "test")
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.Nil(t, rules[0].Methods)

	require.True(t, rules[0].Matches("example.com", "80", "GET", "/"))
	require.True(t, rules[0].Matches("example.com", "80", "DELETE", "/"))
}

func TestCompileRules_ExactPort(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{{Host: "example.com", Ports: []string{"443"}}}, "test")
	require.NoError(t, err)
	require.True(t, rules[0].Matches("example.com", "443", "GET", "/"))
	require.False(t, rules[0].Matches("example.com", "8443", "GET", "/"))
}
