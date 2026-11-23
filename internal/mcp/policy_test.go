package mcp

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
)

func intPtr(i int) *int       { return &i }
func strPtr(s string) *string { return &s }

func TestCompileDefaults(t *testing.T) {
	p, err := Compile(Config{
		Servers: []ServerConfig{{
			Name:  "github",
			Rules: []hostmatch.RuleConfig{{Host: "mcp.github.com"}},
			Tools: []ToolConfig{{Name: "search_repositories"}},
		}},
	})
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Equal(t, DefaultErrorCode, p.ErrorCode())
	require.Equal(t, DefaultErrorMessage, p.ErrorMessage())
}

func TestCompileEmptyConfig(t *testing.T) {
	p, err := Compile(Config{})
	require.NoError(t, err)
	require.Nil(t, p)
}

func TestLoadFromNodeAbsent(t *testing.T) {
	p, err := LoadFromNode(yaml.Node{})
	require.NoError(t, err)
	require.Nil(t, p)
}

func TestLoadFromNodeRoundTrip(t *testing.T) {
	src := `
error:
  code: -32099
  message: "denied"
servers:
  - name: github
    rules:
      - host: "mcp.github.com"
    tools:
      - name: search_repositories
`
	var n yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &n))
	// yaml.Unmarshal into a Node yields a document node; descend to the
	// mapping the way config.LoadConfig does when it pulls cfg.MCP out of
	// the parent struct.
	require.Equal(t, yaml.DocumentNode, n.Kind)
	require.Len(t, n.Content, 1)

	p, err := LoadFromNode(*n.Content[0])
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Equal(t, -32099, p.ErrorCode())
	require.Equal(t, "denied", p.ErrorMessage())
	require.Len(t, p.servers, 1)
}

func TestLoadFromNodeDecodeError(t *testing.T) {
	// Wrong shape: servers should be a list, not a string.
	var n yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(`servers: "not a list"`), &n))
	_, err := LoadFromNode(*n.Content[0])
	require.Error(t, err)
}

func TestCompileCustomError(t *testing.T) {
	p, err := Compile(Config{
		Error: ErrorConfig{Code: intPtr(-32099), Message: strPtr("custom")},
		Servers: []ServerConfig{{
			Name:  "x",
			Rules: []hostmatch.RuleConfig{{Host: "x.example.com"}},
			Tools: []ToolConfig{{Name: "ok"}},
		}},
	})
	require.NoError(t, err)
	require.Equal(t, -32099, p.ErrorCode())
	require.Equal(t, "custom", p.ErrorMessage())
}

func TestCompileValidation(t *testing.T) {
	cases := []struct {
		name   string
		config Config
		errSub string
	}{
		{
			name: "missing server name",
			config: Config{Servers: []ServerConfig{{
				Rules: []hostmatch.RuleConfig{{Host: "x"}},
			}}},
			errSub: "name is required",
		},
		{
			name: "duplicate server name",
			config: Config{Servers: []ServerConfig{
				{Name: "a", Rules: []hostmatch.RuleConfig{{Host: "a"}}},
				{Name: "a", Rules: []hostmatch.RuleConfig{{Host: "b"}}},
			}},
			errSub: "duplicate server name",
		},
		{
			name: "no rules",
			config: Config{Servers: []ServerConfig{{
				Name: "a",
			}}},
			errSub: "at least one rule",
		},
		{
			name: "duplicate tool",
			config: Config{Servers: []ServerConfig{{
				Name:  "a",
				Rules: []hostmatch.RuleConfig{{Host: "a"}},
				Tools: []ToolConfig{{Name: "x"}, {Name: "x"}},
			}}},
			errSub: "duplicate tool name",
		},
		{
			name: "missing tool name",
			config: Config{Servers: []ServerConfig{{
				Name:  "a",
				Rules: []hostmatch.RuleConfig{{Host: "a"}},
				Tools: []ToolConfig{{}},
			}}},
			errSub: "name is required",
		},
		{
			name: "clause with no constraint",
			config: Config{Servers: []ServerConfig{{
				Name:  "a",
				Rules: []hostmatch.RuleConfig{{Host: "a"}},
				Tools: []ToolConfig{{Name: "x", When: []ClauseConfig{{Path: "p"}}}},
			}}},
			errSub: "exactly one of equals, in, matches",
		},
		{
			name: "clause with two constraints",
			config: Config{Servers: []ServerConfig{{
				Name:  "a",
				Rules: []hostmatch.RuleConfig{{Host: "a"}},
				Tools: []ToolConfig{{Name: "x", When: []ClauseConfig{{Path: "p", Equals: "v", Matches: ".*"}}}},
			}}},
			errSub: "exactly one of equals, in, matches",
		},
		{
			name: "bad regex",
			config: Config{Servers: []ServerConfig{{
				Name:  "a",
				Rules: []hostmatch.RuleConfig{{Host: "a"}},
				Tools: []ToolConfig{{Name: "x", When: []ClauseConfig{{Path: "p", Matches: "["}}}},
			}}},
			errSub: "invalid matches regex",
		},
		{
			// A require_tls rule would stop matching plain HTTP, so MatchServer
			// would return nil and the request would skip policy evaluation.
			name: "require_tls on a server rule",
			config: Config{Servers: []ServerConfig{{
				Name:  "a",
				Rules: []hostmatch.RuleConfig{{Host: "a", RequireTLS: true}},
			}}},
			errSub: "require_tls is not supported here",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(tc.config)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errSub)
		})
	}
}

func TestMatchServer(t *testing.T) {
	p := mustCompile(t, Config{Servers: []ServerConfig{
		{
			Name:  "github",
			Rules: []hostmatch.RuleConfig{{Host: "mcp.github.com", Paths: []string{"/mcp"}}},
			Tools: []ToolConfig{{Name: "ok"}},
		},
		{
			Name:  "anthropic",
			Rules: []hostmatch.RuleConfig{{Host: "*.anthropic.com"}},
			Tools: []ToolConfig{{Name: "ok"}},
		},
	}})

	r := func(host, path string) *http.Request {
		u, _ := url.Parse("https://" + host + path)
		return &http.Request{Method: "POST", Host: host, URL: u}
	}

	require.Equal(t, "github", p.MatchServer(r("mcp.github.com", "/mcp")).Name)
	require.Nil(t, p.MatchServer(r("mcp.github.com", "/other")))
	require.Equal(t, "anthropic", p.MatchServer(r("api.anthropic.com", "/")).Name)
	require.Nil(t, p.MatchServer(r("example.com", "/mcp")))
}

func TestEvaluateTool(t *testing.T) {
	p := mustCompile(t, Config{Servers: []ServerConfig{{
		Name:  "github",
		Rules: []hostmatch.RuleConfig{{Host: "mcp.github.com"}},
		Tools: []ToolConfig{
			{Name: "search_repositories"},
			{Name: "create_issue", When: []ClauseConfig{
				{Path: "owner", Equals: "ironsh"},
				{Path: "repo", In: []any{"a", "b"}},
			}},
			{Name: "rename", When: []ClauseConfig{
				{Path: "name", Matches: "^safe-"},
			}},
		},
	}}})
	s := p.MatchServer(httpReq("mcp.github.com", "/", "POST"))
	require.NotNil(t, s)

	// Allowed without constraints.
	allowed, _ := s.EvaluateTool("search_repositories", nil)
	require.True(t, allowed)

	// Tool not in allowlist.
	allowed, reason := s.EvaluateTool("delete_repo", nil)
	require.False(t, allowed)
	require.Equal(t, ReasonToolNotAllowed, reason)

	// Constraints all hold.
	allowed, _ = s.EvaluateTool("create_issue", map[string]any{"owner": "ironsh", "repo": "a"})
	require.True(t, allowed)

	// One constraint fails.
	allowed, reason = s.EvaluateTool("create_issue", map[string]any{"owner": "elsewhere", "repo": "a"})
	require.False(t, allowed)
	require.Equal(t, ReasonArgumentConstraint, reason)

	// In clause negative.
	allowed, reason = s.EvaluateTool("create_issue", map[string]any{"owner": "ironsh", "repo": "c"})
	require.False(t, allowed)
	require.Equal(t, ReasonArgumentConstraint, reason)

	// Missing path.
	allowed, _ = s.EvaluateTool("create_issue", map[string]any{"owner": "ironsh"})
	require.False(t, allowed)

	// Regex match.
	allowed, _ = s.EvaluateTool("rename", map[string]any{"name": "safe-thing"})
	require.True(t, allowed)
	allowed, _ = s.EvaluateTool("rename", map[string]any{"name": "danger"})
	require.False(t, allowed)
}

func mustCompile(t *testing.T, c Config) *Policy {
	t.Helper()
	p, err := Compile(c)
	require.NoError(t, err)
	require.NotNil(t, p)
	return p
}

func httpReq(host, path, method string) *http.Request {
	u, _ := url.Parse("https://" + host + path)
	return &http.Request{Method: method, Host: host, URL: u}
}
