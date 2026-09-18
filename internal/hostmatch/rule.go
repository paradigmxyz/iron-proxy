package hostmatch

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// RuleConfig is the YAML-decoded form of a host/method/path matching rule.
type RuleConfig struct {
	Host    string   `yaml:"host,omitempty"`
	CIDR    string   `yaml:"cidr,omitempty"`
	Ports   []string `yaml:"ports,omitempty"`
	Methods []string `yaml:"methods,omitempty"`
	Paths   []string `yaml:"paths,omitempty"`
}

// Rule is a compiled matching rule ready for use.
type Rule struct {
	Matcher *Matcher
	Ports   map[string]bool // nil = all ports
	Methods map[string]bool // nil = all methods
	Paths   []string        // nil = all paths
}

// Matches returns true if the request matches this rule.
func (r *Rule) Matches(host, port, method, path string) bool {
	if !r.Matcher.Matches(host) {
		return false
	}
	if r.Ports != nil && !r.Ports[port] {
		return false
	}
	if r.Methods != nil && !r.Methods[method] {
		return false
	}
	if r.Paths != nil && !MatchAnyPath(r.Paths, path) {
		return false
	}
	return true
}

// CompileRules compiles a list of RuleConfigs into Rules.
// The prefix is used for error messages (e.g. "allowlist" or "grpc transform \"foo\"").
func CompileRules(configs []RuleConfig, prefix string) ([]Rule, error) {
	var rules []Rule
	for i, rc := range configs {
		if rc.Host != "" && rc.CIDR != "" {
			return nil, fmt.Errorf("%s: rules[%d]: host and cidr are mutually exclusive", prefix, i)
		}
		if rc.Host == "" && rc.CIDR == "" {
			return nil, fmt.Errorf("%s: rules[%d]: one of host or cidr is required", prefix, i)
		}

		var domains, cidrs []string
		if rc.Host != "" {
			domains = []string{rc.Host}
		}
		if rc.CIDR != "" {
			cidrs = []string{rc.CIDR}
		}

		m, err := New(domains, cidrs)
		if err != nil {
			return nil, fmt.Errorf("%s: rules[%d]: %w", prefix, i, err)
		}

		for _, p := range rc.Paths {
			if !strings.HasPrefix(p, "/") {
				return nil, fmt.Errorf("%s: rules[%d]: path %q must start with /", prefix, i, p)
			}
		}

		r := Rule{Matcher: m}
		if len(rc.Ports) > 0 {
			r.Ports = make(map[string]bool, len(rc.Ports))
			for _, port := range rc.Ports {
				if port == "" || strings.ContainsAny(port, "*?/\\") {
					return nil, fmt.Errorf("%s: rules[%d]: invalid exact port %q", prefix, i, port)
				}
				r.Ports[port] = true
			}
		}
		if !isWildcard(rc.Methods) {
			r.Methods = make(map[string]bool, len(rc.Methods))
			for _, method := range rc.Methods {
				r.Methods[strings.ToUpper(method)] = true
			}
		}
		if len(rc.Paths) > 0 {
			r.Paths = rc.Paths
		}

		rules = append(rules, r)
	}
	return rules, nil
}

func isWildcard(methods []string) bool {
	return len(methods) == 0 || (len(methods) == 1 && methods[0] == "*")
}

// MatchAnyRule returns true if the request matches any rule in the list.
func MatchAnyRule(rules []Rule, req *http.Request) bool {
	host, port := HostPort(req)
	for _, r := range rules {
		if r.Matches(host, port, req.Method, req.URL.Path) {
			return true
		}
	}
	return false
}

// HostPort returns the normalized request hostname and effective destination
// port. It preserves explicit non-default ports instead of allowing a
// hostname rule to silently authorize every service on that host.
func HostPort(req *http.Request) (string, string) {
	host := StripPort(req.Host)
	if _, port, err := net.SplitHostPort(req.Host); err == nil {
		return host, port
	}
	if req.URL != nil && strings.EqualFold(req.URL.Scheme, "https") || req.TLS != nil {
		return host, "443"
	}
	return host, "80"
}
