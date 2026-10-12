package hostmatch

import (
	"fmt"
	"net/http"
	"strings"
)

// RuleConfig is the YAML-decoded form of a host/method/path matching rule.
type RuleConfig struct {
	Host    string   `yaml:"host,omitempty"`
	CIDR    string   `yaml:"cidr,omitempty"`
	Methods []string `yaml:"methods,omitempty"`
	Paths   []string `yaml:"paths,omitempty"`
	// RequireTLS limits the rule to requests that arrived inside TLS (a
	// MITM'd or direct HTTPS request). A plain-HTTP request never matches.
	// Set it on rules that inject a credential, so the credential is never
	// sent upstream in clear text. Do not set it on a rule that enforces a
	// policy (judge, header_allowlist, ...): there it would let plain-HTTP
	// requests skip the policy.
	RequireTLS bool `yaml:"require_tls,omitempty"`
}

// Rule is a compiled matching rule ready for use.
type Rule struct {
	Matcher    *Matcher
	Methods    map[string]bool // nil = all methods
	Paths      []string        // nil = all paths
	RequireTLS bool            // true = plain-HTTP requests never match
}

// MatchesRequest returns true if req matches this rule, including the
// require_tls condition. Prefer it over Matches whenever the request is at
// hand.
func (r *Rule) MatchesRequest(req *http.Request) bool {
	if r.RequireTLS && req.TLS == nil {
		return false
	}
	return r.Matches(StripPort(req.Host), req.Method, req.URL.Path)
}

// Matches returns true if host, method and path match this rule. It cannot
// see the connection, so it does not apply require_tls: use MatchesRequest
// for real requests.
func (r *Rule) Matches(host, method, path string) bool {
	if !r.Matcher.Matches(host) {
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

		r := Rule{Matcher: m, RequireTLS: rc.RequireTLS}
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
	for _, r := range rules {
		if r.MatchesRequest(req) {
			return true
		}
	}
	return false
}
