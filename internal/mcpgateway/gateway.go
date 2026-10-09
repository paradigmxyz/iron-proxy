// Package mcpgateway implements host-based routing for MCP Streamable HTTP
// servers after MCP policy enforcement has allowed a request.
package mcpgateway

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// Config is the YAML shape of the top-level mcp_gateway block.
type Config struct {
	Routes []RouteConfig `yaml:"routes"`
}

// RouteConfig maps one client-facing MCP host/path to a concrete upstream.
type RouteConfig struct {
	Name        string                 `yaml:"name"`
	Rules       []hostmatch.RuleConfig `yaml:"rules"`
	Upstream    string                 `yaml:"upstream"`
	Credentials []CredentialConfig     `yaml:"credentials"`
}

// CredentialConfig injects a secret into a matched upstream request.
type CredentialConfig struct {
	Source  yaml.Node    `yaml:"source"`
	Inject  InjectConfig `yaml:"inject"`
	Require *bool        `yaml:"require,omitempty"`
}

// InjectConfig chooses the outbound location and optional formatting for a
// gateway credential.
type InjectConfig struct {
	Header     string `yaml:"header,omitempty"`
	QueryParam string `yaml:"query_param,omitempty"`
	Formatter  string `yaml:"formatter,omitempty"`
}

// Gateway is the compiled, immutable form of Config.
type Gateway struct {
	routes []*Route
}

// Route is a compiled gateway route.
type Route struct {
	Name        string
	rules       []hostmatch.Rule
	upstream    url.URL
	credentials []credential
}

type credential struct {
	source     secrets.Source
	inject     InjectConfig
	require    bool
	formatter  *template.Template
	sourceName string
}

// AppliedRoute describes the gateway rewrite applied to a request.
type AppliedRoute struct {
	Name                  string
	Upstream              string
	RequestURL            string
	InjectedCredentialIDs []string
}

// LoadFromNode decodes a raw yaml.Node into a Config and compiles it. An empty
// node returns nil so callers can treat an absent mcp_gateway block normally.
func LoadFromNode(node yaml.Node) (*Gateway, error) {
	if node.Kind == 0 {
		return nil, nil
	}
	var c Config
	if err := node.Decode(&c); err != nil {
		return nil, fmt.Errorf("decoding mcp_gateway config: %w", err)
	}
	return Compile(c)
}

// Compile validates and compiles a Config into a Gateway. Returns nil when no
// routes are configured.
func Compile(c Config) (*Gateway, error) {
	if len(c.Routes) == 0 {
		return nil, nil
	}
	g := &Gateway{routes: make([]*Route, 0, len(c.Routes))}
	seen := make(map[string]bool, len(c.Routes))
	for i, rc := range c.Routes {
		if rc.Name == "" {
			return nil, fmt.Errorf("mcp_gateway.routes[%d]: name is required", i)
		}
		if seen[rc.Name] {
			return nil, fmt.Errorf("mcp_gateway.routes[%d]: duplicate route name %q", i, rc.Name)
		}
		seen[rc.Name] = true
		if len(rc.Rules) == 0 {
			return nil, fmt.Errorf("mcp_gateway.routes[%q]: at least one rule is required", rc.Name)
		}
		rules, err := hostmatch.CompileRules(rc.Rules, fmt.Sprintf("mcp_gateway.routes[%q]", rc.Name))
		if err != nil {
			return nil, err
		}
		upstream, err := normalizeUpstream(rc.Name, rc.Upstream)
		if err != nil {
			return nil, err
		}
		creds, err := compileCredentials(rc.Name, rc.Credentials)
		if err != nil {
			return nil, err
		}
		g.routes = append(g.routes, &Route{
			Name:        rc.Name,
			rules:       rules,
			upstream:    upstream,
			credentials: creds,
		})
	}
	return g, nil
}

func normalizeUpstream(routeName, raw string) (url.URL, error) {
	if raw == "" {
		return url.URL{}, fmt.Errorf("mcp_gateway.routes[%q].upstream is required", routeName)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return url.URL{}, fmt.Errorf("mcp_gateway.routes[%q].upstream must be a valid URL: %w", routeName, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return url.URL{}, fmt.Errorf("mcp_gateway.routes[%q].upstream must use http or https", routeName)
	}
	if u.Host == "" {
		return url.URL{}, fmt.Errorf("mcp_gateway.routes[%q].upstream must include a host", routeName)
	}
	if u.Fragment != "" {
		return url.URL{}, fmt.Errorf("mcp_gateway.routes[%q].upstream must not include a fragment", routeName)
	}
	return *u, nil
}

func compileCredentials(routeName string, configs []CredentialConfig) ([]credential, error) {
	creds := make([]credential, 0, len(configs))
	for i, cc := range configs {
		src, err := secrets.BuildSource(cc.Source, nil)
		if err != nil {
			return nil, fmt.Errorf("mcp_gateway.routes[%q].credentials[%d]: %w", routeName, i, err)
		}
		if err := validateInject(routeName, i, cc.Inject); err != nil {
			return nil, err
		}
		require := true
		if cc.Require != nil {
			require = *cc.Require
		}
		cred := credential{
			source:     src,
			inject:     cc.Inject,
			require:    require,
			sourceName: src.Name(),
		}
		if cc.Inject.Formatter != "" {
			tmpl, err := template.New(fmt.Sprintf("mcp_gateway.routes[%q].credentials[%d]", routeName, i)).Funcs(templateFuncs).Parse(cc.Inject.Formatter)
			if err != nil {
				return nil, fmt.Errorf("mcp_gateway.routes[%q].credentials[%d]: parsing formatter: %w", routeName, i, err)
			}
			cred.formatter = tmpl
		}
		creds = append(creds, cred)
	}
	return creds, nil
}

var templateFuncs = template.FuncMap{
	"base64": func(parts ...string) string {
		return base64.StdEncoding.EncodeToString([]byte(strings.Join(parts, "")))
	},
}

func validateInject(routeName string, i int, cfg InjectConfig) error {
	hasHeader := cfg.Header != ""
	hasQuery := cfg.QueryParam != ""
	if !hasHeader && !hasQuery {
		return fmt.Errorf("mcp_gateway.routes[%q].credentials[%d]: inject must specify either header or query_param", routeName, i)
	}
	if hasHeader && hasQuery {
		return fmt.Errorf("mcp_gateway.routes[%q].credentials[%d]: inject cannot specify both header and query_param", routeName, i)
	}
	return nil
}

// Match returns the first route whose rules match the request, or nil.
func (g *Gateway) Match(req *http.Request) *Route {
	if g == nil {
		return nil
	}
	host, port := hostmatch.HostPort(req)
	for _, route := range g.routes {
		for _, rule := range route.rules {
			if rule.Matches(host, port, req.Method, req.URL.Path) {
				return route
			}
		}
	}
	return nil
}

// Apply injects route credentials into req and returns the upstream target
// components the proxy should use when constructing the outbound request.
func (r *Route) Apply(ctx context.Context, req *http.Request) (*AppliedRoute, error) {
	if r == nil {
		return nil, nil
	}
	upstream := r.upstream
	applied := &AppliedRoute{
		Name: r.Name,
	}
	for _, cred := range r.credentials {
		value, err := cred.source.Get(ctx)
		if err != nil {
			if cred.require {
				return nil, fmt.Errorf("gateway credential %q unavailable: %w", cred.sourceName, err)
			}
			continue
		}
		value, err = formatCredential(cred.formatter, value)
		if err != nil {
			return nil, fmt.Errorf("formatting gateway credential %q: %w", cred.sourceName, err)
		}
		if cred.inject.Header != "" {
			req.Header.Set(cred.inject.Header, value)
			applied.InjectedCredentialIDs = append(applied.InjectedCredentialIDs, cred.sourceName+":header:"+http.CanonicalHeaderKey(cred.inject.Header))
			continue
		}
		q := req.URL.Query()
		q.Set(cred.inject.QueryParam, value)
		req.URL.RawQuery = q.Encode()
		applied.InjectedCredentialIDs = append(applied.InjectedCredentialIDs, cred.sourceName+":query:"+cred.inject.QueryParam)
	}
	applied.Upstream = upstream.String()
	upstream.RawQuery = mergeRawQuery(r.upstream.RawQuery, req.URL.RawQuery)
	applied.RequestURL = upstream.String()
	return applied, nil
}

func formatCredential(tmpl *template.Template, value string) (string, error) {
	if tmpl == nil {
		return value, nil
	}
	var b strings.Builder
	err := tmpl.Execute(&b, struct {
		Value string
	}{Value: value})
	if err != nil {
		return "", err
	}
	return b.String(), nil
}

func mergeRawQuery(base, request string) string {
	if base == "" {
		return request
	}
	if request == "" {
		return base
	}
	return base + "&" + request
}
