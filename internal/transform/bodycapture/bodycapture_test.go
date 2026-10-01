package bodycapture

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// newTransform constructs a bodyCapture for testing without going through the
// YAML factory, with response capture off — the shipped default. Tests pin
// behavior, not parsing.
func newTransform(t *testing.T, maxBytes int64, rules []hostmatch.RuleConfig) *bodyCapture {
	t.Helper()
	compiled, err := hostmatch.CompileRules(rules, "body_capture")
	require.NoError(t, err)
	return &bodyCapture{
		rules:               compiled,
		maxRequestBodyBytes: maxBytes,
	}
}

// newResponseTransform is newTransform with response capture enabled and both
// caps pinned, for the tests that exercise the response half.
func newResponseTransform(t *testing.T, maxRequest, maxResponse int64, rules []hostmatch.RuleConfig) *bodyCapture {
	t.Helper()
	compiled, err := hostmatch.CompileRules(rules, "body_capture")
	require.NoError(t, err)
	return &bodyCapture{
		rules:                compiled,
		maxRequestBodyBytes:  maxRequest,
		captureResponseBody:  true,
		maxResponseBodyBytes: maxResponse,
	}
}

// makeRequest builds a POST request to the given host/path with body bytes,
// wrapped in a BufferedBody (matches what the pipeline does in production
// before any transform runs).
func makeRequest(t *testing.T, host, path string, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest("POST", "http://"+host+path, strings.NewReader(body))
	req.Host = host
	// Wrap the body in a BufferedBody — the production pipeline does this in
	// proxy.go before invoking transforms. The maxBytes here is the global
	// BodyLimits cap, not the body_capture transform's own cap.
	req.Body = transform.NewBufferedBody(req.Body, 1024*1024)
	return req
}

func TestBodyCapture_MatchedRequest_PopulatesTctx(t *testing.T) {
	bc := newTransform(t, 16*1024, []hostmatch.RuleConfig{
		{Host: "api.anthropic.com", Methods: []string{"POST"}, Paths: []string{"/v1/messages"}},
	})
	body := `{"messages":[{"role":"user","content":"hello"}]}`
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", body)
	tctx := &transform.TransformContext{}

	res, err := bc.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	require.NotNil(t, tctx.BodyCapture, "BodyCapture should be populated when a rule matches")
	require.Equal(t, body, tctx.BodyCapture.RequestBody())
	require.False(t, tctx.BodyCapture.RequestBodyTruncated())

	// The transform also annotates its own trace entry so request_transforms
	// self-documents the capture without duplicating the body.
	ann := tctx.DrainAnnotations()
	require.Equal(t, len(body), ann["captured_bytes"])
	require.Equal(t, false, ann["truncated"])
}

func TestBodyCapture_NoMatch_DoesNotPopulateTctx(t *testing.T) {
	bc := newTransform(t, 16*1024, []hostmatch.RuleConfig{
		{Host: "api.anthropic.com"},
	})
	req := makeRequest(t, "example.com", "/anywhere", `{"hello":"world"}`)
	tctx := &transform.TransformContext{}

	res, err := bc.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	require.Nil(t, tctx.BodyCapture, "BodyCapture should be nil when no rule matches")
	require.Nil(t, tctx.DrainAnnotations(), "no trace annotations when no rule matches")
}

func TestBodyCapture_BodyExceedsCap_TruncatesWithFlag(t *testing.T) {
	const cap = 32
	bc := newTransform(t, cap, []hostmatch.RuleConfig{
		{Host: "api.anthropic.com"},
	})
	// 100 chars of body — should be truncated to 32.
	body := strings.Repeat("x", 100)
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", body)
	tctx := &transform.TransformContext{}

	_, err := bc.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	require.NotNil(t, tctx.BodyCapture)
	require.Equal(t, cap, len(tctx.BodyCapture.RequestBody()), "captured body should be exactly cap bytes")
	require.Equal(t, strings.Repeat("x", cap), tctx.BodyCapture.RequestBody())
	require.True(t, tctx.BodyCapture.RequestBodyTruncated(), "truncated flag should be set")

	ann := tctx.DrainAnnotations()
	require.Equal(t, cap, ann["captured_bytes"], "captured_bytes reflects the truncated length")
	require.Equal(t, true, ann["truncated"])
}

func TestBodyCapture_Truncation_TrimsPartialUTF8Rune(t *testing.T) {
	// Cap falls in the middle of a multi-byte rune. The captured body must be
	// valid UTF-8 (no dangling fragment) so it renders cleanly in audit JSON.
	// "€" is 3 bytes (0xE2 0x82 0xAC). With a body of "ab€" (5 bytes) and a
	// cap of 4, the naive cut keeps "ab" + the first 2 bytes of "€".
	const cap = 4
	bc := newTransform(t, cap, []hostmatch.RuleConfig{
		{Host: "api.anthropic.com"},
	})
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", "ab€")
	tctx := &transform.TransformContext{}

	_, err := bc.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	require.NotNil(t, tctx.BodyCapture)
	got := tctx.BodyCapture.RequestBody()
	require.True(t, utf8.ValidString(got), "captured body must be valid UTF-8, got %q", got)
	require.Equal(t, "ab", got, "partial trailing rune should be trimmed back to a boundary")
	require.True(t, tctx.BodyCapture.RequestBodyTruncated())
}

func TestBodyCapture_EmptyBody_DoesNotPopulateTctx(t *testing.T) {
	bc := newTransform(t, 16*1024, []hostmatch.RuleConfig{
		{Host: "api.anthropic.com"},
	})
	// GET with no body — req.Body is http.NoBody or a BufferedBody wrapping
	// an empty reader. Either way, we shouldn't emit a BodyCapture with an
	// empty string (clutters audit logs with empty-body events).
	req := httptest.NewRequest("GET", "http://api.anthropic.com/health", nil)
	req.Host = "api.anthropic.com"
	req.Body = transform.NewBufferedBody(req.Body, 1024)
	tctx := &transform.TransformContext{}

	res, err := bc.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	require.Nil(t, tctx.BodyCapture, "empty body should not populate BodyCapture")
	require.Nil(t, tctx.DrainAnnotations(), "empty body should not annotate the trace")
}

func TestBodyCapture_MultipleRules_FirstMatchCapturesOnce(t *testing.T) {
	// Two rules that both match the same request. The transform should still
	// capture exactly one body (hostmatch.MatchAnyRule short-circuits on first
	// match, but the body is also read only once via io.ReadAll regardless).
	bc := newTransform(t, 16*1024, []hostmatch.RuleConfig{
		{Host: "api.anthropic.com"},
		{Host: "*.anthropic.com"},
	})
	body := `{"prompt":"test"}`
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", body)
	tctx := &transform.TransformContext{}

	_, err := bc.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	require.NotNil(t, tctx.BodyCapture)
	require.Equal(t, body, tctx.BodyCapture.RequestBody())
	require.False(t, tctx.BodyCapture.RequestBodyTruncated())
}

func TestBodyCapture_TransformResponse_IsNoopByDefault(t *testing.T) {
	// Response capture is opt-in. Without `capture_response_body: true` the
	// response leg must not touch the response body at all — an existing
	// configuration sees exactly the behavior it saw before. The tests in
	// response_test.go cover the opted-in path.
	bc := newTransform(t, 16*1024, []hostmatch.RuleConfig{
		{Host: "api.anthropic.com"},
	})
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)
	resp := &http.Response{
		StatusCode: 200,
		Body:       transform.NewBufferedBody(io.NopCloser(strings.NewReader("response body")), 1024),
	}
	tctx := &transform.TransformContext{}

	res, err := bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	// The response BufferedBody must NOT have been read (Len() == -1 means
	// "never buffered"). If a future change starts reading it, this test
	// fails and forces a deliberate update.
	require.Equal(t, -1, transform.RequireBufferedBody(resp.Body).Len(),
		"response body must not be read — would break SSE streaming")
	require.Nil(t, tctx.BodyCapture, "response transform must not populate BodyCapture")
}

func TestBodyCapture_BodyCaptureInterface(t *testing.T) {
	// Compile-time + runtime check that *capture satisfies transform.BodyCapture.
	var _ transform.BodyCapture = (*capture)(nil)

	c := &capture{requestBody: "hi", requestBodyTruncated: true}
	require.Equal(t, "hi", c.RequestBody())
	require.True(t, c.RequestBodyTruncated())
	require.Equal(t, "", c.ResponseBody())
	require.False(t, c.ResponseBodyTruncated())
}
