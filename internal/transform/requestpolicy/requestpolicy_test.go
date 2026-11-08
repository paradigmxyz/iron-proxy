package requestpolicy

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

func policyFromYAML(t *testing.T, source string) (transform.Transformer, error) {
	t.Helper()
	var document yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(source), &document))
	return factory(*document.Content[0], slog.Default())
}

func run(t *testing.T, p transform.Transformer, req *http.Request) (transform.TransformAction, map[string]any) {
	t.Helper()
	req.Body = transform.NewBufferedBody(req.Body, 1024*1024)
	tctx := &transform.TransformContext{}
	result, err := p.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	return result.Action, tctx.DrainAnnotations()
}

func TestRequestPolicy_RequestShape(t *testing.T) {
	p, err := policyFromYAML(t, `rules:
  - host: api.example
    port: "443"
    path: /lookup
    http_methods: [GET, HEAD]
    require_empty_body: true
    query:
      mode: exact
      parameters:
        - {name: q, required: true, value_pattern: "alpha|alphabet"}
        - {name: token, required: true, exact_values: [stub]}
        - {name: format, exact_values: [JSON], case_insensitive: true}
  - host: api.example
    port: "443"
    path: /artifact
    http_methods: [GET]
    require_empty_body: true
    query: {mode: empty}
`)
	require.NoError(t, err)
	const target = "https://api.example/lookup?q=alphabet&token=stub&format=json"
	cases := []struct {
		name, method, target, body, reason string
		mutate                             func(*http.Request)
	}{
		{"allowed GET", "GET", target, "", "", nil},
		{"allowed HEAD", "HEAD", target, "", "", nil},
		{"CONNECT transport", "CONNECT", "api.example:443", "", "", nil},
		{"other host", "GET", "https://other.example/", "", "", nil},
		{"other port", "GET", "https://api.example:8443/", "", "", nil},
		{"optional parameter omitted", "GET", "https://api.example/lookup?token=stub&q=alpha", "", "", nil},
		{"decoded value", "GET", "https://api.example/lookup?token=stub&q=alpha%62et", "", "", nil},
		{"empty query", "GET", "https://api.example/artifact", "", "", nil},
		{"unknown parameter", "GET", target + "&extra=x", "", "query", nil},
		{"duplicate pattern value", "GET", target + "&q=alpha", "", "query", nil},
		{"missing required parameter", "GET", "https://api.example/lookup?q=alpha", "", "query", nil},
		{"case sensitive value", "GET", "https://api.example/lookup?q=alpha&token=STUB", "", "query", nil},
		{"pattern prefix", "GET", "https://api.example/lookup?q=prefixalphabet&token=stub", "", "query", nil},
		{"pattern suffix", "GET", "https://api.example/lookup?q=alphabetsuffix&token=stub", "", "query", nil},
		{"artifact query", "GET", "https://api.example/artifact?extra=x", "", "query", nil},
		{"wrong path", "GET", "https://api.example/other", "", "path", nil},
		{"wrong method", "POST", target, "", "http_method", nil},
		{"request body", "GET", target, "data", "content_length", nil},
		{"chunked body", "GET", target, "data", "transfer_encoding", func(r *http.Request) { r.ContentLength = -1; r.TransferEncoding = []string{"chunked"} }},
		{"hidden body", "GET", target, "data", "body", func(r *http.Request) { r.ContentLength = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			if tc.mutate != nil {
				tc.mutate(req)
			}
			action, annotations := run(t, p, req)
			if tc.reason == "" {
				require.Equal(t, transform.ActionContinue, action)
				if tc.method == http.MethodConnect {
					require.Equal(t, "tunnel", annotations["decision"])
				}
			} else {
				require.Equal(t, transform.ActionReject, action)
				require.Equal(t, tc.reason, annotations["reason"])
			}
		})
	}
}

func TestRequestPolicy_ExactQueryValues(t *testing.T) {
	p, err := policyFromYAML(t, `rules:
  - host: api.example
    port: "443"
    path: /
    http_methods: [GET]
    query:
      mode: exact
      parameters:
        - {name: project, required: true, exact_values: [first, second, second]}
        - {name: label, required: true, exact_values: [Hello World], case_insensitive: true}
`)
	require.NoError(t, err)
	cases := []struct {
		name, query string
		allow       bool
	}{
		{"reordered and decoded", "label=HELLO%20WORLD&project=second&project=first&project=second", true},
		{"missing value", "project=first&project=second&label=hello+world", false},
		{"extra value", "project=first&project=second&project=second&project=second&label=hello+world", false},
		{"changed value", "project=first&project=second&project=changed&label=hello+world", false},
		{"different decoded value", "project=first&project=second&project=second&label=hello%2520world", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, _ := run(t, p, httptest.NewRequest("GET", "https://api.example/?"+tc.query, nil))
			require.Equal(t, tc.allow, action == transform.ActionContinue)
		})
	}
}

func TestRequestPolicy_InvalidConfig(t *testing.T) {
	const source = `rules:
  - host: api.example
    port: "443"
    path: /
    http_methods: [GET]
    query:
      mode: exact
      parameters:
        - {name: key, required: true, exact_values: [value]}
`
	cases := []struct{ name, old, replacement string }{
		{"wildcard host", "api.example", `"*.example"`},
		{"invalid port", `"443"`, `"0"`},
		{"encoded path", "path: /", "path: /%61"},
		{"CONNECT method", "[GET]", "[CONNECT]"},
		{"empty parameter list", "parameters:\n        - {name: key, required: true, exact_values: [value]}", "parameters: []"},
		{"missing matcher", ", exact_values: [value]", ""},
		{"empty exact values", "[value]", "[]"},
		{"empty pattern", "exact_values: [value]", `value_pattern: ""`},
		{"both matchers", "exact_values: [value]", "exact_values: [value], value_pattern: value"},
		{"null matcher", "exact_values: [value]", "value_pattern: null"},
		{"invalid regex", "exact_values: [value]", `value_pattern: "["`},
		{"nonscalar pattern", "exact_values: [value]", "value_pattern: [value]"},
		{"pattern with case option", "exact_values: [value]", "value_pattern: value, case_insensitive: true"},
		{"nonboolean case option", "exact_values: [value]", `exact_values: [value], case_insensitive: "true"`},
		{"unknown config field", "rules:", "rulez:"},
		{"unknown rule field", "http_methods:", "http_method:"},
		{"unknown query field", "mode:", "modes:"},
		{"unknown parameter field", "required:", "require:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := policyFromYAML(t, strings.Replace(source, tc.old, tc.replacement, 1))
			require.Error(t, err)
		})
	}
}
