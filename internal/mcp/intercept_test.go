package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func newTestPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := Compile(Config{
		Servers: []ServerConfig{{
			Name:  "github",
			Rules: []hostmatch.RuleConfig{{Host: "mcp.github.com"}},
			Tools: []ToolConfig{
				{Name: "search_repositories"},
				{Name: "create_issue", When: []ClauseConfig{
					{Path: "owner", Equals: "ironsh"},
				}},
			},
		}},
	})
	require.NoError(t, err)
	return p
}

func newJSONRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	u, _ := url.Parse("https://mcp.github.com/mcp")
	r := &http.Request{
		Method:        http.MethodPost,
		Host:          "mcp.github.com",
		URL:           u,
		Header:        http.Header{"Content-Type": {"application/json"}},
		ContentLength: int64(len(body)),
		Body:          transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), 0),
	}
	return r
}

func TestEvaluateRequestAllow(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))
	require.NotNil(t, s)

	req := newJSONRequest(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_repositories","arguments":{"q":"foo"}}}`)
	tr := &Trace{Server: s.Name}
	resp, err := p.EvaluateRequest(s, req, tr)
	require.NoError(t, err)
	require.Nil(t, resp)
	require.Len(t, tr.Messages, 1)
	require.Equal(t, DecisionAllow, tr.Messages[0].Decision)
	require.Equal(t, "search_repositories", tr.Messages[0].Tool)
	require.Equal(t, map[string]any{"q": "foo"}, tr.Messages[0].Arguments)
	require.Empty(t, tr.Messages[0].RawArguments)
}

func TestEvaluateRequestArgumentsTruncated(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))

	huge := strings.Repeat("x", 1000)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_repositories","arguments":{"q":"` + huge + `"}}}`
	req := newJSONRequest(t, body)
	tr := &Trace{Server: s.Name}
	_, err := p.EvaluateRequest(s, req, tr)
	require.NoError(t, err)
	require.Len(t, tr.Messages, 1)
	require.Nil(t, tr.Messages[0].Arguments)
	require.Len(t, tr.Messages[0].RawArguments, AuditArgumentsMaxLen)
	require.True(t, strings.HasSuffix(tr.Messages[0].RawArguments, "..."))
}

func TestEvaluateRequestDenyToolNotAllowed(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))

	req := newJSONRequest(t, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}`)
	tr := &Trace{Server: s.Name}
	resp, err := p.EvaluateRequest(s, req, tr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var msg rpcMessage
	require.NoError(t, json.Unmarshal(body, &msg))
	require.Equal(t, "7", string(msg.ID))
	require.NotNil(t, msg.Error)
	require.Equal(t, DefaultErrorCode, msg.Error.Code)

	require.Len(t, tr.Messages, 1)
	require.Equal(t, DecisionDeny, tr.Messages[0].Decision)
	require.Equal(t, ReasonToolNotAllowed, tr.Messages[0].Reason)
}

func TestEvaluateRequestDenyArgumentConstraint(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))

	req := newJSONRequest(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"someoneelse"}}}`)
	tr := &Trace{Server: s.Name}
	resp, err := p.EvaluateRequest(s, req, tr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, ReasonArgumentConstraint, tr.Messages[0].Reason)
}

func TestEvaluateRequestPassThroughNonToolsCall(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))

	req := newJSONRequest(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	tr := &Trace{Server: s.Name}
	resp, err := p.EvaluateRequest(s, req, tr)
	require.NoError(t, err)
	require.Nil(t, resp)
	require.Len(t, tr.Messages, 1)
	require.Equal(t, DecisionAllow, tr.Messages[0].Decision)
	require.Equal(t, "tools/list", tr.Messages[0].Method)
}

func TestEvaluateRequestSkipsNonJSON(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))

	u, _ := url.Parse("https://mcp.github.com/mcp")
	req := &http.Request{
		Method: http.MethodGet,
		Host:   "mcp.github.com",
		URL:    u,
		Header: http.Header{},
		Body:   transform.NewBufferedBody(io.NopCloser(strings.NewReader("")), 0),
	}
	tr := &Trace{Server: s.Name}
	resp, err := p.EvaluateRequest(s, req, tr)
	require.NoError(t, err)
	require.Nil(t, resp)
	require.Empty(t, tr.Messages)
}

func TestEvaluateRequestMalformedDenies(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))

	req := newJSONRequest(t, `not json`)
	tr := &Trace{Server: s.Name}
	resp, err := p.EvaluateRequest(s, req, tr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, ReasonMalformedJSONRPC, tr.Messages[0].Reason)
}

func TestEvaluateRequestBatchAllAllowed(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))

	body := `[
		{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_repositories"}},
		{"jsonrpc":"2.0","id":2,"method":"tools/list"}
	]`
	req := newJSONRequest(t, body)
	tr := &Trace{Server: s.Name}
	resp, err := p.EvaluateRequest(s, req, tr)
	require.NoError(t, err)
	require.Nil(t, resp)
	require.Len(t, tr.Messages, 2)
}

func TestEvaluateRequestBatchAnyDeniedDeniesAll(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))

	body := `[
		{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_repositories"}},
		{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repo"}}
	]`
	req := newJSONRequest(t, body)
	tr := &Trace{Server: s.Name}
	resp, err := p.EvaluateRequest(s, req, tr)
	require.NoError(t, err)
	require.NotNil(t, resp)

	respBody, _ := io.ReadAll(resp.Body)
	var msgs []rpcMessage
	require.NoError(t, json.Unmarshal(respBody, &msgs))
	require.Len(t, msgs, 2)
	for _, m := range msgs {
		require.NotNil(t, m.Error)
	}
}

func TestWrapResponseBodyJSON(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))

	tr := &Trace{Server: s.Name}
	tr.recordToolsListID(json.RawMessage(`1`))

	body := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search_repositories"},{"name":"hidden"},{"name":"create_issue"}]}}`
	wrapped, err := p.WrapResponseBody(s, "application/json", io.NopCloser(strings.NewReader(body)), tr)
	require.NoError(t, err)

	out, err := io.ReadAll(wrapped)
	require.NoError(t, err)

	var msg rpcMessage
	require.NoError(t, json.Unmarshal(out, &msg))
	var result map[string]any
	require.NoError(t, json.Unmarshal(msg.Result, &result))
	tools := result["tools"].([]any)
	require.Len(t, tools, 2)
}

func TestWrapResponseBodySSEFiltersToolsList(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))

	tr := &Trace{Server: s.Name}
	tr.recordToolsListID(json.RawMessage(`1`))

	stream := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"search_repositories\"},{\"name\":\"hidden\"}]}}\n\n" +
		": keepalive\n\n" +
		"data: not-json\n\n"
	wrapped, err := p.WrapResponseBody(s, "text/event-stream", io.NopCloser(strings.NewReader(stream)), tr)
	require.NoError(t, err)

	out, err := io.ReadAll(wrapped)
	require.NoError(t, err)
	outStr := string(out)

	require.Contains(t, outStr, "search_repositories")
	require.NotContains(t, outStr, "hidden")
	require.Contains(t, outStr, ": keepalive")
	require.Contains(t, outStr, "data: not-json")
}

// TestWrapResponseBodyJSONLeavesUnrelatedToolsArrayAlone is a regression test
// for the bug where any result containing a top-level "tools" array was
// rewritten, even when the response was not a tools/list reply (e.g. a
// tools/call result whose payload happens to contain a "tools" array). The
// trace records no tools/list id, so the response must pass through verbatim.
func TestWrapResponseBodyJSONLeavesUnrelatedToolsArrayAlone(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))

	body := `{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"hidden"},{"name":"another_unknown"}],"summary":"ok"}}`
	tr := &Trace{Server: s.Name} // no tools/list id recorded
	wrapped, err := p.WrapResponseBody(s, "application/json", io.NopCloser(strings.NewReader(body)), tr)
	require.NoError(t, err)

	out, err := io.ReadAll(wrapped)
	require.NoError(t, err)
	require.Equal(t, body, string(out), "non tools/list response with a tools array must be untouched")
}

// TestWrapResponseBodySSELeavesUnrelatedToolsArrayAlone is the SSE counterpart
// to TestWrapResponseBodyJSONLeavesUnrelatedToolsArrayAlone.
func TestWrapResponseBodySSELeavesUnrelatedToolsArrayAlone(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))

	stream := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[{\"name\":\"hidden\"},{\"name\":\"another_unknown\"}]}}\n\n"
	tr := &Trace{Server: s.Name}
	wrapped, err := p.WrapResponseBody(s, "text/event-stream", io.NopCloser(strings.NewReader(stream)), tr)
	require.NoError(t, err)

	out, err := io.ReadAll(wrapped)
	require.NoError(t, err)
	require.Contains(t, string(out), "hidden")
	require.Contains(t, string(out), "another_unknown")
}

func TestEvaluateRequestEnforcesPostRegardlessOfContentType(t *testing.T) {
	p := newTestPolicy(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`

	cases := []struct {
		name        string
		contentType string
	}{
		{name: "json", contentType: "application/json"},
		{name: "json with casing and parameter", contentType: "Application/JSON; charset=utf-8"},
		{name: "plain text", contentType: "text/plain"},
		{name: "form", contentType: "application/x-www-form-urlencoded"},
		{name: "missing"},
		{name: "malformed", contentType: "application/json, text/plain"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newJSONRequest(t, body)
			if tc.contentType == "" {
				req.Header.Del("Content-Type")
			} else {
				req.Header.Set("Content-Type", tc.contentType)
			}
			s := p.MatchServer(req)
			require.NotNil(t, s)

			tr := &Trace{Server: s.Name}
			resp, err := p.EvaluateRequest(s, req, tr)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Len(t, tr.Messages, 1)
			require.Equal(t, DecisionDeny, tr.Messages[0].Decision)
			require.Equal(t, ReasonToolNotAllowed, tr.Messages[0].Reason)
		})
	}
}

func TestWrapResponseBodyOtherContentTypePassesThrough(t *testing.T) {
	p := newTestPolicy(t)
	s := p.MatchServer(newJSONRequest(t, "{}"))

	body := bytes.NewReader([]byte("plain text"))
	wrapped, err := p.WrapResponseBody(s, "text/plain", io.NopCloser(body), &Trace{Server: s.Name})
	require.NoError(t, err)

	out, err := io.ReadAll(wrapped)
	require.NoError(t, err)
	require.Equal(t, "plain text", string(out))
}
