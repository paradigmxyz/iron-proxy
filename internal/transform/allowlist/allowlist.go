// Package allowlist implements a default-deny domain and CIDR allowlist transform.
package allowlist

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("allowlist", factory)
}

// Allowlist is a default-deny transform that checks request hosts, methods,
// and paths against a set of rules.
type Allowlist struct {
	rules []hostmatch.Rule
	warn  bool
}

type allowlistConfig struct {
	Domains []string               `yaml:"domains"`
	CIDRs   []string               `yaml:"cidrs"`
	Rules   []hostmatch.RuleConfig `yaml:"rules"`
	Warn    bool                   `yaml:"warn"`
}

func factory(cfg yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var c allowlistConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing allowlist config: %w", err)
	}
	return newFromConfig(c)
}

func newFromConfig(cfg allowlistConfig) (*Allowlist, error) {
	var rules []hostmatch.Rule

	// Flat domains → rules with no method/path restrictions.
	for _, d := range cfg.Domains {
		m, err := hostmatch.New([]string{d}, nil)
		if err != nil {
			return nil, err
		}
		rules = append(rules, hostmatch.Rule{Matcher: m})
	}

	// Flat CIDRs → rules with no method/path restrictions.
	for _, c := range cfg.CIDRs {
		m, err := hostmatch.New(nil, []string{c})
		if err != nil {
			return nil, err
		}
		rules = append(rules, hostmatch.Rule{Matcher: m})
	}

	// Explicit rules with optional method/path restrictions.
	compiled, err := hostmatch.CompileRules(cfg.Rules, "allowlist")
	if err != nil {
		return nil, err
	}
	rules = append(rules, compiled...)

	return &Allowlist{rules: rules, warn: cfg.Warn}, nil
}

// New creates an Allowlist from domain globs and CIDR strings.
// All methods and paths are allowed. This is the backwards-compatible constructor.
func New(domains []string, cidrs []string) (*Allowlist, error) {
	return newFromConfig(allowlistConfig{Domains: domains, CIDRs: cidrs})
}

func (a *Allowlist) Name() string { return "allowlist" }

func (a *Allowlist) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if a.matches(tctx, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	if a.warn {
		tctx.Annotate("action", "warn")
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	return &transform.TransformResult{Action: transform.ActionReject}, nil
}

// matches reports whether req is allowed by any rule. The tunnel preflight is
// a synthetic CONNECT with no path, so method and path restrictions can never
// match it. It is checked against the host only. Method and path rules are
// enforced on the requests inside the tunnel, which run through the pipeline
// again (MITM and plain HTTP), or the tunnel cannot carry them (sni-only,
// where only host-only rules match the passthrough check).
func (a *Allowlist) matches(tctx *transform.TransformContext, req *http.Request) bool {
	if !tctx.TunnelPreflight {
		return hostmatch.MatchAnyRule(a.rules, req)
	}
	host := hostmatch.StripPort(req.Host)
	for _, r := range a.rules {
		if r.Matcher.Matches(host) {
			return true
		}
	}
	return false
}

func (a *Allowlist) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}
