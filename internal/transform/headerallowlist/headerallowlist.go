// Package headerallowlist implements a default-deny request header allowlist
// transform. Any request header whose canonical name is not in the configured
// list (and does not match a configured regex pattern) is stripped before the
// request is sent upstream.
package headerallowlist

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("header_allowlist", factory)
}

type config struct {
	Headers []string               `yaml:"headers"`
	Rules   []hostmatch.RuleConfig `yaml:"rules"`
}

// HeaderAllowlist strips request headers not in the configured allowlist.
type HeaderAllowlist struct {
	matchers []headerMatcher
	rules    []hostmatch.Rule // nil = apply to all requests
}

// headerMatcher matches a single allowlist entry. Exactly one of name or re is set.
type headerMatcher struct {
	name string
	re   *regexp.Regexp
}

func (m headerMatcher) matches(canonical string) bool {
	if m.re != nil {
		return m.re.MatchString(canonical)
	}
	return m.name == canonical
}

func factory(cfg yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing header_allowlist config: %w", err)
	}
	return newFromConfig(c)
}

func newFromConfig(c config) (*HeaderAllowlist, error) {
	if len(c.Headers) == 0 {
		return nil, fmt.Errorf("header_allowlist: at least one header is required")
	}

	matchers, err := parseHeaderMatchers(c.Headers)
	if err != nil {
		return nil, err
	}

	rules, err := hostmatch.CompileRules(c.Rules, "header_allowlist")
	if err != nil {
		return nil, err
	}

	return &HeaderAllowlist{matchers: matchers, rules: rules}, nil
}

// parseHeaderMatchers compiles allowlist entries. Patterns delimited by
// "/.../" are compiled as case-insensitive regular expressions matched against
// canonical header names; all other entries are literal header names.
func parseHeaderMatchers(patterns []string) ([]headerMatcher, error) {
	matchers := make([]headerMatcher, 0, len(patterns))
	for _, p := range patterns {
		if len(p) >= 2 && strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") {
			re, err := regexp.Compile("(?i)" + p[1:len(p)-1])
			if err != nil {
				return nil, fmt.Errorf("header_allowlist: invalid headers regex %q: %w", p, err)
			}
			matchers = append(matchers, headerMatcher{re: re})
			continue
		}
		matchers = append(matchers, headerMatcher{name: http.CanonicalHeaderKey(p)})
	}
	return matchers, nil
}

func (h *HeaderAllowlist) Name() string { return "header_allowlist" }

func (h *HeaderAllowlist) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if len(h.rules) > 0 && !hostmatch.MatchAnyRule(h.rules, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	var stripped []string
	for name := range req.Header {
		if h.allowed(name) {
			continue
		}
		// Delete the exact map key: Header.Del canonicalizes its argument and
		// would miss keys stored with preserved wire casing (internal/headers).
		delete(req.Header, name)
		stripped = append(stripped, name)
	}

	if len(stripped) > 0 {
		tctx.Annotate("stripped_headers", stripped)
	}

	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (h *HeaderAllowlist) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (h *HeaderAllowlist) allowed(name string) bool {
	canonical := http.CanonicalHeaderKey(name)
	for _, m := range h.matchers {
		if m.matches(canonical) {
			return true
		}
	}
	return false
}
