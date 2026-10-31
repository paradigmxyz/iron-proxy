// Package requestpolicy implements exact HTTP request-shape policies.
package requestpolicy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"gopkg.in/yaml.v3"
)

type queryParameterConfig struct {
	Name            string   `yaml:"name"`
	Required        bool     `yaml:"required"`
	ExactValues     []string `yaml:"exact_values,omitempty"`
	ValuePattern    string   `yaml:"value_pattern,omitempty"`
	CaseInsensitive bool     `yaml:"case_insensitive,omitempty"`
}

type queryConfig struct {
	Mode       string                 `yaml:"mode"`
	Parameters []queryParameterConfig `yaml:"parameters"`
}

type ruleConfig struct {
	Host             string      `yaml:"host"`
	Port             string      `yaml:"port"`
	Path             string      `yaml:"path"`
	HTTPMethods      []string    `yaml:"http_methods"`
	RequireEmptyBody bool        `yaml:"require_empty_body"`
	Query            queryConfig `yaml:"query"`
}

type config struct {
	Rules []ruleConfig `yaml:"rules"`
}

type queryParameter struct {
	required        bool
	caseInsensitive bool
	exactValues     []string
	valuePattern    *regexp.Regexp
}

type rule struct {
	host             string
	port             string
	path             string
	httpMethods      map[string]struct{}
	requireEmptyBody bool
	queryMode        string
	queryParameters  map[string]queryParameter
}

type policy struct{ rules []rule }

func init() { transform.Register("request_policy", factory) }

func factory(node yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var cfg config
	if err := transform.DecodeKnownFields(node, &cfg); err != nil {
		return nil, fmt.Errorf("parsing request_policy config: %w", err)
	}
	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("request_policy: at least one rule is required")
	}
	p := &policy{}
	for i, source := range cfg.Rules {
		compiled, err := compileRule(source)
		if err != nil {
			return nil, fmt.Errorf("request_policy: rules[%d]: %w", i, err)
		}
		p.rules = append(p.rules, compiled)
	}
	return p, nil
}

func compileRule(source ruleConfig) (rule, error) {
	host := strings.ToLower(strings.TrimSuffix(source.Host, "."))
	if host == "" || strings.ContainsAny(host, "*?/\\@") {
		return rule{}, fmt.Errorf("host must be an exact hostname")
	}
	portNumber, err := strconv.ParseUint(source.Port, 10, 16)
	if err != nil || portNumber == 0 {
		return rule{}, fmt.Errorf("port must be an integer from 1 through 65535")
	}
	if source.Path == "" || !strings.HasPrefix(source.Path, "/") {
		return rule{}, fmt.Errorf("path must be an absolute exact path")
	}
	if strings.ContainsAny(source.Path, "*?[]\\") {
		return rule{}, fmt.Errorf("path must not contain glob or query syntax")
	}
	if decoded, err := url.PathUnescape(source.Path); err != nil || decoded != source.Path {
		return rule{}, fmt.Errorf("path must use its canonical unescaped spelling")
	}
	if len(source.HTTPMethods) == 0 {
		return rule{}, fmt.Errorf("http_methods must be non-empty")
	}
	result := rule{
		host:             host,
		port:             source.Port,
		path:             source.Path,
		httpMethods:      make(map[string]struct{}, len(source.HTTPMethods)),
		requireEmptyBody: source.RequireEmptyBody,
		queryMode:        source.Query.Mode,
		queryParameters:  make(map[string]queryParameter, len(source.Query.Parameters)),
	}
	for _, method := range source.HTTPMethods {
		method = strings.ToUpper(method)
		if method == "" || method == http.MethodConnect || strings.ContainsAny(method, " \t\r\n") {
			return rule{}, fmt.Errorf("invalid HTTP method %q", method)
		}
		result.httpMethods[method] = struct{}{}
	}
	if result.queryMode != "empty" && result.queryMode != "exact" {
		return rule{}, fmt.Errorf("query.mode must be empty or exact")
	}
	if result.queryMode == "empty" && len(source.Query.Parameters) != 0 {
		return rule{}, fmt.Errorf("empty query mode must not define parameters")
	}
	if result.queryMode == "exact" && len(source.Query.Parameters) == 0 {
		return rule{}, fmt.Errorf("exact query mode requires parameters")
	}
	for i, parameter := range source.Query.Parameters {
		if parameter.Name == "" || strings.ContainsAny(parameter.Name, "&=; \t\r\n") {
			return rule{}, fmt.Errorf("query.parameters[%d] has invalid name", i)
		}
		if _, exists := result.queryParameters[parameter.Name]; exists {
			return rule{}, fmt.Errorf("query parameter %q is duplicated", parameter.Name)
		}
		if (len(parameter.ExactValues) == 0) == (parameter.ValuePattern == "") {
			return rule{}, fmt.Errorf("query parameter %q requires exactly one of exact_values or value_pattern", parameter.Name)
		}
		compiled := queryParameter{
			required: parameter.Required, caseInsensitive: parameter.CaseInsensitive, exactValues: parameter.ExactValues,
		}
		if parameter.ValuePattern != "" {
			if parameter.CaseInsensitive {
				return rule{}, fmt.Errorf("query parameter %q cannot combine value_pattern with case_insensitive", parameter.Name)
			}
			pattern, err := regexp.Compile(parameter.ValuePattern)
			if err != nil {
				return rule{}, fmt.Errorf("query parameter %q has invalid value_pattern: %w", parameter.Name, err)
			}
			pattern.Longest()
			compiled.valuePattern = pattern
		} else {
			if compiled.caseInsensitive {
				for i := range compiled.exactValues {
					compiled.exactValues[i] = strings.ToLower(compiled.exactValues[i])
				}
			}
			slices.Sort(compiled.exactValues)
		}
		result.queryParameters[parameter.Name] = compiled
	}
	return result, nil
}

func (p *policy) Name() string { return "request_policy" }

func (p *policy) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	host, port := hostmatch.HostPort(req)
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	hostPortMatched := false
	pathMatched := false
	for i := range p.rules {
		rule := &p.rules[i]
		if rule.host != host || rule.port != port {
			continue
		}
		hostPortMatched = true
		if req.Method == http.MethodConnect {
			tctx.Annotate("decision", "tunnel")
			return continueResult(), nil
		}
		if requestPath(req) != rule.path {
			continue
		}
		pathMatched = true
		if _, ok := rule.httpMethods[req.Method]; !ok {
			continue
		}
		if rule.requireEmptyBody {
			if reason := validateEmptyBody(req); reason != "" {
				return reject(tctx, reason), nil
			}
		}
		if reason := validateQuery(req.URL, rule); reason != "" {
			return reject(tctx, reason), nil
		}
		tctx.Annotate("decision", "allow")
		return continueResult(), nil
	}
	if !hostPortMatched {
		return continueResult(), nil
	}
	if !pathMatched {
		return reject(tctx, "path"), nil
	}
	return reject(tctx, "http_method"), nil
}

func (p *policy) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return continueResult(), nil
}

func validateEmptyBody(req *http.Request) string {
	if len(req.TransferEncoding) != 0 || req.Header.Get("Transfer-Encoding") != "" {
		return "transfer_encoding"
	}
	if req.Header.Get("Content-Encoding") != "" {
		return "content_encoding"
	}
	if req.ContentLength != 0 {
		return "content_length"
	}
	if req.Body == nil || req.Body == http.NoBody {
		return ""
	}
	body, err := io.ReadAll(req.Body)
	if err != nil || len(body) != 0 {
		return "body"
	}
	return ""
}

func validateQuery(requestURL *url.URL, rule *rule) string {
	if requestURL == nil {
		return "query"
	}
	if rule.queryMode == "empty" {
		if requestURL.RawQuery != "" {
			return "query"
		}
		return ""
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil {
		return "query"
	}
	for name, actual := range values {
		parameter, ok := rule.queryParameters[name]
		if !ok {
			return "query"
		}
		if parameter.valuePattern != nil {
			if len(actual) != 1 {
				return "query"
			}
			match := parameter.valuePattern.FindStringIndex(actual[0])
			if match == nil || match[0] != 0 || match[1] != len(actual[0]) {
				return "query"
			}
			continue
		}
		if parameter.caseInsensitive {
			for i := range actual {
				actual[i] = strings.ToLower(actual[i])
			}
		}
		slices.Sort(actual)
		if !slices.Equal(actual, parameter.exactValues) {
			return "query"
		}
	}
	for name, parameter := range rule.queryParameters {
		if parameter.required && len(values[name]) == 0 {
			return "query"
		}
	}
	return ""
}

func requestPath(req *http.Request) string {
	if req.URL == nil {
		return ""
	}
	if req.URL.RawPath != "" {
		return req.URL.EscapedPath()
	}
	return req.URL.Path
}

func continueResult() *transform.TransformResult {
	return &transform.TransformResult{Action: transform.ActionContinue}
}

func reject(tctx *transform.TransformContext, reason string) *transform.TransformResult {
	tctx.Annotate("decision", "reject")
	tctx.Annotate("reason", reason)
	return &transform.TransformResult{Action: transform.ActionReject}
}
