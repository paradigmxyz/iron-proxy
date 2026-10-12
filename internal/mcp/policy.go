// Package mcp implements an MCP-aware policy that inspects Streamable HTTP
// JSON-RPC traffic to enforce per-server tool allowlists with optional
// argument constraints. It runs alongside the proxy's transform pipeline as a
// first-class interceptor: requests are evaluated before forwarding upstream
// and responses are filtered per-event before reaching the client, which
// matches MCP's long-lived SSE response semantics that the request/response
// transform contract does not.
package mcp

import (
	"fmt"
	"net/http"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
)

// Default JSON-RPC error code and message used when policy denies a tools/call.
// Both are configurable via the top-level mcp.error block.
const (
	DefaultErrorCode    = -32001
	DefaultErrorMessage = "blocked by iron-proxy policy"
)

// Reason codes recorded on denial audit messages.
const (
	ReasonToolNotAllowed     = "tool_not_allowed"
	ReasonArgumentConstraint = "argument_constraint"
	ReasonOversizeBody       = "oversize_body"
	ReasonMalformedJSONRPC   = "malformed_jsonrpc"
	ReasonBatchNotSupported  = "batch_not_supported"
)

// Decision values recorded on audit messages.
const (
	DecisionAllow    = "allow"
	DecisionDeny     = "deny"
	DecisionFiltered = "filtered"
)

// Direction values recorded on audit messages.
const (
	DirectionRequest  = "request"
	DirectionResponse = "response"
)

// Config is the YAML shape of the top-level mcp: block.
type Config struct {
	Error   ErrorConfig    `yaml:"error"`
	Servers []ServerConfig `yaml:"servers"`
}

// ErrorConfig customizes the JSON-RPC error envelope used for policy denials.
// Both fields use defaults when unset.
type ErrorConfig struct {
	Code    *int    `yaml:"code"`
	Message *string `yaml:"message"`
}

// ServerConfig declares a logical MCP server: a set of host/path rules that
// identify its traffic plus the allowlist of tools that may be called on it.
type ServerConfig struct {
	Name  string                 `yaml:"name"`
	Rules []hostmatch.RuleConfig `yaml:"rules"`
	Tools []ToolConfig           `yaml:"tools"`
}

// ToolConfig is a single allowed tool, optionally constrained by argument
// matchers. All matchers AND together; an omitted when block means the tool
// name match is sufficient.
type ToolConfig struct {
	Name string         `yaml:"name"`
	When []ClauseConfig `yaml:"when"`
}

// ClauseConfig is a single argument constraint. Exactly one of equals, in, or
// matches must be set.
type ClauseConfig struct {
	Path    string `yaml:"path"`
	Equals  any    `yaml:"equals"`
	In      []any  `yaml:"in"`
	Matches string `yaml:"matches"`
}

// Policy is the compiled, runtime form of the mcp config.
type Policy struct {
	errorCode    int
	errorMessage string
	servers      []*Server
}

// Server is a compiled MCP server definition.
type Server struct {
	Name  string
	rules []hostmatch.Rule
	tools map[string]*Tool
	// allowedNames is the set of tool names allowed on this server, derived
	// from tools at compile time. Cached so the response-side filter does
	// not rebuild the map on every response.
	allowedNames map[string]bool
}

// Tool is a compiled tool allowlist entry with optional argument constraints.
type Tool struct {
	Name    string
	clauses []clause
}

// LoadFromNode decodes a raw yaml.Node into a Config and compiles it. An
// empty node (the mcp: block absent from the source document) returns
// (nil, nil) so callers can treat "no MCP policy" as a normal case.
func LoadFromNode(node yaml.Node) (*Policy, error) {
	if node.Kind == 0 {
		return nil, nil
	}
	var c Config
	if err := node.Decode(&c); err != nil {
		return nil, fmt.Errorf("decoding mcp config: %w", err)
	}
	return Compile(c)
}

// Compile validates and compiles a Config into a Policy. Returns nil when the
// supplied config has no servers — the caller can treat this as "MCP policy
// not configured".
func Compile(c Config) (*Policy, error) {
	if len(c.Servers) == 0 {
		return nil, nil
	}

	p := &Policy{
		errorCode:    DefaultErrorCode,
		errorMessage: DefaultErrorMessage,
	}
	if c.Error.Code != nil {
		p.errorCode = *c.Error.Code
	}
	if c.Error.Message != nil {
		p.errorMessage = *c.Error.Message
	}

	seenNames := make(map[string]bool)
	for i, sc := range c.Servers {
		if sc.Name == "" {
			return nil, fmt.Errorf("mcp.servers[%d]: name is required", i)
		}
		if seenNames[sc.Name] {
			return nil, fmt.Errorf("mcp.servers[%d]: duplicate server name %q", i, sc.Name)
		}
		seenNames[sc.Name] = true

		if len(sc.Rules) == 0 {
			return nil, fmt.Errorf("mcp.servers[%q]: at least one rule is required", sc.Name)
		}

		rules, err := hostmatch.CompileRules(sc.Rules, fmt.Sprintf("mcp.servers[%q]", sc.Name))
		if err != nil {
			return nil, err
		}

		s := &Server{
			Name:         sc.Name,
			rules:        rules,
			tools:        make(map[string]*Tool, len(sc.Tools)),
			allowedNames: make(map[string]bool, len(sc.Tools)),
		}

		for j, tc := range sc.Tools {
			if tc.Name == "" {
				return nil, fmt.Errorf("mcp.servers[%q].tools[%d]: name is required", sc.Name, j)
			}
			if _, dup := s.tools[tc.Name]; dup {
				return nil, fmt.Errorf("mcp.servers[%q].tools: duplicate tool name %q", sc.Name, tc.Name)
			}
			clauses, err := compileClauses(tc.When, fmt.Sprintf("mcp.servers[%q].tools[%q]", sc.Name, tc.Name))
			if err != nil {
				return nil, err
			}
			s.tools[tc.Name] = &Tool{Name: tc.Name, clauses: clauses}
			s.allowedNames[tc.Name] = true
		}

		p.servers = append(p.servers, s)
	}

	return p, nil
}

func (p *Policy) ErrorCode() int       { return p.errorCode }
func (p *Policy) ErrorMessage() string { return p.errorMessage }

// MatchServer returns the first server whose rules match the request, or nil.
func (p *Policy) MatchServer(req *http.Request) *Server {
	if p == nil {
		return nil
	}
	host := hostmatch.StripPort(req.Host)
	for _, s := range p.servers {
		for _, r := range s.rules {
			if r.Matches(host, req.Method, req.URL.Path) {
				return s
			}
		}
	}
	return nil
}

// AllowedToolNames returns the precompiled set of tool names allowed on this
// server. The map is shared (not copied) and must not be mutated.
func (s *Server) AllowedToolNames() map[string]bool {
	return s.allowedNames
}

// EvaluateTool checks whether a tool call is allowed under this server's
// policy. params is the decoded JSON-RPC params (typically a map containing
// "name" and "arguments"). Returns the decision reason on deny.
func (s *Server) EvaluateTool(toolName string, args any) (allowed bool, reason string) {
	t, ok := s.tools[toolName]
	if !ok {
		return false, ReasonToolNotAllowed
	}
	if len(t.clauses) == 0 {
		return true, ""
	}
	for _, cl := range t.clauses {
		if !cl.evaluate(args) {
			return false, ReasonArgumentConstraint
		}
	}
	return true, ""
}
