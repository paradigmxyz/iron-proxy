package mcpgateway

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
)

func boolPtr(v bool) *bool { return &v }

func TestCompileAndApply(t *testing.T) {
	t.Setenv("MCP_TOKEN", "real-token")

	g, err := Compile(Config{
		Routes: []RouteConfig{{
			Name:     "github",
			Rules:    []hostmatch.RuleConfig{{Host: "github.mcp.local", Paths: []string{"/mcp", "/mcp/*"}}},
			Upstream: "https://mcp.github.com/v1",
			Credentials: []CredentialConfig{{
				Source: mustYAMLNode(t, `type: env
var: MCP_TOKEN
`),
				Inject: InjectConfig{
					Header:    "Authorization",
					Formatter: "Bearer {{ .Value }}",
				},
			}},
		}},
	})
	require.NoError(t, err)

	req := newRequest(t, "https://github.mcp.local/mcp/tools?existing=1")
	route := g.Match(req)
	require.NotNil(t, route)

	applied, err := route.Apply(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "github", applied.Name)
	require.Equal(t, "https://mcp.github.com/v1", applied.Upstream)
	require.Equal(t, "https://mcp.github.com/v1?existing=1", applied.RequestURL)
	require.Equal(t, "Bearer real-token", req.Header.Get("Authorization"))
	require.Equal(t, []string{"MCP_TOKEN:header:Authorization"}, applied.InjectedCredentialIDs)
}

func TestApplyInjectsQueryParam(t *testing.T) {
	t.Setenv("MCP_TOKEN", "real-token")

	g, err := Compile(Config{
		Routes: []RouteConfig{{
			Name:     "github",
			Rules:    []hostmatch.RuleConfig{{Host: "github.mcp.local"}},
			Upstream: "https://mcp.github.com",
			Credentials: []CredentialConfig{{
				Source: mustYAMLNode(t, `type: env
var: MCP_TOKEN
`),
				Inject: InjectConfig{QueryParam: "access_token"},
			}},
		}},
	})
	require.NoError(t, err)

	req := newRequest(t, "https://github.mcp.local/mcp?existing=1")
	applied, err := g.Match(req).Apply(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "real-token", req.URL.Query().Get("access_token"))
	require.Equal(t, "https://mcp.github.com", applied.Upstream)
	require.Equal(t, "https://mcp.github.com?access_token=real-token&existing=1", applied.RequestURL)
	require.Equal(t, []string{"MCP_TOKEN:query:access_token"}, applied.InjectedCredentialIDs)
}

func TestApplyUsesFixedUpstreamPath(t *testing.T) {
	g, err := Compile(Config{
		Routes: []RouteConfig{{
			Name:     "github",
			Rules:    []hostmatch.RuleConfig{{Host: "github.mcp.local"}},
			Upstream: "https://mcp.github.com/v1/",
		}},
	})
	require.NoError(t, err)

	req := newRequest(t, "https://github.mcp.local/mcp/")
	applied, err := g.Match(req).Apply(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "https://mcp.github.com/v1/", applied.Upstream)
	require.Equal(t, "https://mcp.github.com/v1/", applied.RequestURL)
}

func TestApplyRequiredCredentialFailure(t *testing.T) {
	g, err := Compile(Config{
		Routes: []RouteConfig{{
			Name:     "github",
			Rules:    []hostmatch.RuleConfig{{Host: "github.mcp.local"}},
			Upstream: "https://mcp.github.com",
			Credentials: []CredentialConfig{{
				Source: mustYAMLNode(t, `type: env
var: MISSING_MCP_TOKEN
`),
				Inject: InjectConfig{Header: "Authorization"},
			}},
		}},
	})
	require.NoError(t, err)

	req := newRequest(t, "https://github.mcp.local/mcp")
	_, err = g.Match(req).Apply(context.Background(), req)
	require.Error(t, err)
	require.Contains(t, err.Error(), `gateway credential "MISSING_MCP_TOKEN" unavailable`)
}

func TestApplyOptionalCredentialFailure(t *testing.T) {
	g, err := Compile(Config{
		Routes: []RouteConfig{{
			Name:     "github",
			Rules:    []hostmatch.RuleConfig{{Host: "github.mcp.local"}},
			Upstream: "https://mcp.github.com",
			Credentials: []CredentialConfig{{
				Source: mustYAMLNode(t, `type: env
var: MISSING_MCP_TOKEN
`),
				Inject:  InjectConfig{Header: "Authorization"},
				Require: boolPtr(false),
			}},
		}},
	})
	require.NoError(t, err)

	req := newRequest(t, "https://github.mcp.local/mcp")
	applied, err := g.Match(req).Apply(context.Background(), req)
	require.NoError(t, err)
	require.Empty(t, req.Header.Get("Authorization"))
	require.Empty(t, applied.InjectedCredentialIDs)
}

func TestCompileValidation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name:    "missing name",
			cfg:     Config{Routes: []RouteConfig{{Upstream: "https://example.com"}}},
			wantErr: "name is required",
		},
		{
			name:    "missing rules",
			cfg:     Config{Routes: []RouteConfig{{Name: "github", Upstream: "https://example.com"}}},
			wantErr: "at least one rule is required",
		},
		{
			name: "invalid upstream scheme",
			cfg: Config{Routes: []RouteConfig{{
				Name:     "github",
				Rules:    []hostmatch.RuleConfig{{Host: "github.mcp.local"}},
				Upstream: "ftp://example.com",
			}}},
			wantErr: "upstream must use http or https",
		},
		{
			name: "missing upstream host",
			cfg: Config{Routes: []RouteConfig{{
				Name:     "github",
				Rules:    []hostmatch.RuleConfig{{Host: "github.mcp.local"}},
				Upstream: "https:///v1",
			}}},
			wantErr: "upstream must include a host",
		},
		{
			name: "invalid credential injection",
			cfg: Config{Routes: []RouteConfig{{
				Name:     "github",
				Rules:    []hostmatch.RuleConfig{{Host: "github.mcp.local"}},
				Upstream: "https://example.com",
				Credentials: []CredentialConfig{{
					Source: mustYAMLNode(t, `type: env
var: MCP_TOKEN
`),
					Inject: InjectConfig{Header: "Authorization", QueryParam: "token"},
				}},
			}}},
			wantErr: "inject cannot specify both header and query_param",
		},
		{
			// A route rule that stops matching would send the request to r.Host
			// instead of the route upstream.
			name: "require_tls on a route rule",
			cfg: Config{Routes: []RouteConfig{{
				Name:     "github",
				Rules:    []hostmatch.RuleConfig{{Host: "github.mcp.local", RequireTLS: true}},
				Upstream: "https://example.com",
			}}},
			wantErr: "require_tls is not supported here",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(tc.cfg)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func newRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return &http.Request{
		Method: http.MethodPost,
		URL:    u,
		Host:   u.Host,
		Header: http.Header{},
		Body:   http.NoBody,
	}
}

func mustYAMLNode(t *testing.T, src string) yaml.Node {
	t.Helper()
	var doc yaml.Node
	err := yaml.NewDecoder(strings.NewReader(src)).Decode(&doc)
	require.NoError(t, err)
	require.Equal(t, yaml.DocumentNode, doc.Kind)
	require.NotEmpty(t, doc.Content)
	return *doc.Content[0]
}
