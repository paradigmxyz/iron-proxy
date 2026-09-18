package jsonrpc

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func testPolicy(t *testing.T, max int64) transform.Transformer {
	t.Helper()
	if max == 0 {
		max = 1024
	}
	var node yaml.Node
	require.NoError(t, node.Encode(config{MaxBodyBytes: max, Rules: []ruleConfig{{
		Host: "rpc.example", Port: "443", Path: "/rpc", HTTPMethods: []string{"POST"},
		AllowedMethods: []string{"eth_chainId", "eth_call"},
	}}}))
	result, err := factory(node, slog.Default())
	require.NoError(t, err)
	return result
}

func request(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/json")
	req.Body = transform.NewBufferedBody(req.Body, 1024*1024)
	return req
}

func decision(t *testing.T, p transform.Transformer, req *http.Request) (transform.TransformAction, map[string]any) {
	t.Helper()
	tctx := &transform.TransformContext{}
	result, err := p.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	return result.Action, tctx.DrainAnnotations()
}

func TestJSONRPC_AllowsSingleAndAllAllowedBatch(t *testing.T) {
	p := testPolicy(t, 0)
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`,
		`[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":"two","method":"eth_call","params":[{},"latest"]}]`,
	} {
		action, annotations := decision(t, p, request(t, "POST", "https://rpc.example/rpc", body))
		require.Equal(t, transform.ActionContinue, action)
		require.Equal(t, "allow", annotations["decision"])
	}
}

func TestJSONRPC_RejectsMalformedDuplicateNotificationAndDisallowedBatches(t *testing.T) {
	p := testPolicy(t, 0)
	cases := []struct{ name, body, reason string }{
		{"malformed", `{`, "malformed_json"},
		{"duplicate top", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","method":"eth_call"}`, "malformed_json"},
		{"duplicate nested", `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":{"to":"0x1","to":"0x2"}}`, "malformed_json"},
		{"notification", `{"jsonrpc":"2.0","method":"eth_chainId"}`, "notification"},
		{"null id", `{"jsonrpc":"2.0","id":null,"method":"eth_chainId"}`, "notification"},
		{"empty batch", `[]`, "empty_batch"},
		{"unknown", `{"jsonrpc":"2.0","id":1,"method":"eth_unknown"}`, "method"},
		{"mixed batch", `[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"eth_sendTransaction"}]`, "method"},
		{"invalid params", `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":"secret"}`, "invalid_envelope"},
		{"extra field", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","secret":"x"}`, "invalid_envelope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, annotations := decision(t, p, request(t, "POST", "https://rpc.example/rpc", tc.body))
			require.Equal(t, transform.ActionReject, action)
			require.Equal(t, tc.reason, annotations["reason"])
		})
	}
}

func TestJSONRPC_RejectsTransportAndEndpointBypasses(t *testing.T) {
	p := testPolicy(t, 1024)
	valid := `{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}`
	cases := []struct {
		name   string
		mutate func(*http.Request)
		reason string
	}{
		{"wrong path", func(r *http.Request) { r.URL.Path = "/other" }, "path"},
		{"encoded path", func(r *http.Request) { r.URL.RawPath = "/%72pc" }, "path"},
		{"wrong method", func(r *http.Request) { r.Method = "GET" }, "http_method"},
		{"wrong port", func(r *http.Request) { r.Host = "rpc.example:8443" }, ""},
		{"websocket", func(r *http.Request) {
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Upgrade", "websocket")
		}, "websocket"},
		{"chunked", func(r *http.Request) { r.TransferEncoding = []string{"chunked"}; r.ContentLength = -1 }, "transfer_encoding"},
		{"compressed", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, "content_encoding"},
		{"missing length", func(r *http.Request) { r.ContentLength = -1 }, "content_length"},
		{"incomplete", func(r *http.Request) { r.ContentLength++ }, "body_incomplete"},
		{"oversize", func(r *http.Request) { r.ContentLength = 1025 }, "body_oversize"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := request(t, "POST", "https://rpc.example/rpc", valid)
			tc.mutate(req)
			action, annotations := decision(t, p, req)
			if tc.reason == "" {
				require.Equal(t, transform.ActionContinue, action, "policy applies only to exact endpoint")
				return
			}
			require.Equal(t, transform.ActionReject, action)
			require.Equal(t, tc.reason, annotations["reason"])
		})
	}
}

func TestJSONRPC_CONNECTIsTransportOnly(t *testing.T) {
	p := testPolicy(t, 0)
	req := request(t, "CONNECT", "https://rpc.example:443", "")
	req.Host = "rpc.example:443"
	action, annotations := decision(t, p, req)
	require.Equal(t, transform.ActionContinue, action)
	require.Equal(t, "tunnel", annotations["decision"])
}

func TestJSONRPCRejectsUnknownYAMLFieldsAtEveryNestingLevel(t *testing.T) {
	for name, source := range map[string]string{
		"config": `unexpected: true
rules: []`,
		"rule": `rules:
  - host: rpc.example
    port: "443"
    path: /rpc
    http_methods: [POST]
    allowed_methods: [eth_call]
    unexpected: true`,
	} {
		t.Run(name, func(t *testing.T) {
			var document yaml.Node
			require.NoError(t, yaml.Unmarshal([]byte(source), &document))
			_, err := factory(*document.Content[0], slog.Default())
			require.Error(t, err)
			require.Contains(t, err.Error(), "field unexpected")
		})
	}
}
