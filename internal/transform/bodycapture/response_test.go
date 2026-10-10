package bodycapture

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// The tests in this file cover the response half of body_capture. The two
// load-bearing ones are TestBodyCaptureResponse_NeverBlocksOnANeverEndingBody
// and TestBodyCaptureResponse_CapTruncatesInsteadOfStalling: an audit copy that
// can wait on a slow model reply — or that applies back-pressure when it runs
// out of room — is a client-visible hang, which is exactly the trade-off the
// package used to refuse response capture over. Both are asserted under a
// deadline so a regression fails the suite instead of hanging it.

const testDeadline = 3 * time.Second

// steppedBody is an upstream response body that hands out its chunks one at a
// time and then BLOCKS on hold until the test releases it. With a nil hold it
// simply ends. It stands in for a streaming model reply that is still being
// generated.
type steppedBody struct {
	mu       sync.Mutex
	chunks   [][]byte
	leftover []byte
	hold     <-chan struct{}
	closed   bool
}

func newSteppedBody(hold <-chan struct{}, chunks ...string) *steppedBody {
	b := &steppedBody{hold: hold}
	for _, c := range chunks {
		b.chunks = append(b.chunks, []byte(c))
	}
	return b
}

func (b *steppedBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if len(b.leftover) > 0 {
		n := copy(p, b.leftover)
		b.leftover = b.leftover[n:]
		b.mu.Unlock()
		return n, nil
	}
	if len(b.chunks) > 0 {
		chunk := b.chunks[0]
		b.chunks = b.chunks[1:]
		n := copy(p, chunk)
		b.leftover = chunk[n:]
		b.mu.Unlock()
		return n, nil
	}
	hold := b.hold
	b.mu.Unlock()
	if hold != nil {
		// Out of chunks but not done: the model is still thinking. A
		// buffer-then-forward implementation parks here forever.
		<-hold
	}
	return 0, io.EOF
}

func (b *steppedBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

func (b *steppedBody) wasClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// makeResponse wraps body in a BufferedBody the way proxy.handleHTTP does
// before the response pipeline runs, with optional headers.
func makeResponse(body io.ReadCloser, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		// 0 = unlimited, matching the proxy's default BodyLimits.
		Body: transform.NewBufferedBody(body, 0),
	}
}

// forwardToClient drains the response body the way the proxy's writeResponse /
// streamSSE do — through StreamingReader, chunk by chunk — and returns what the
// client saw. Fails the test if it takes longer than testDeadline.
func forwardToClient(t *testing.T, resp *http.Response) string {
	t.Helper()
	reader := transform.RequireBufferedBody(resp.Body).StreamingReader()
	type result struct {
		data string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(reader)
		done <- result{string(data), err}
	}()
	select {
	case r := <-done:
		require.NoError(t, r.err)
		return r.data
	case <-time.After(testDeadline):
		t.Fatal("forwarding the response body to the client did not finish within the deadline")
		return ""
	}
}

func messagesRules() []hostmatch.RuleConfig {
	return []hostmatch.RuleConfig{
		{Host: "api.anthropic.com", Methods: []string{"POST"}, Paths: []string{"/v1/messages"}},
	}
}

func TestBodyCaptureResponse_TeesRatherThanBuffering(t *testing.T) {
	bc := newResponseTransform(t, 16*1024, defaultMaxResponseBodyBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)
	resp := makeResponse(io.NopCloser(strings.NewReader(`{"content":[{"type":"text","text":"hi"}]}`)), nil)
	tctx := &transform.TransformContext{}

	_, err := bc.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	res, err := bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	// The contract that keeps the proxy honest: after TransformResponse the body
	// is still UNREAD (Len() == -1 means "never buffered"), and the capture is
	// still empty. If a future change goes back to reading the body here, both
	// of these fail.
	require.Equal(t, -1, transform.RequireBufferedBody(resp.Body).Len(),
		"TransformResponse must not buffer the response body")
	require.Equal(t, "", tctx.BodyCapture.ResponseBody(),
		"nothing should be captured until the body actually streams")

	got := forwardToClient(t, resp)
	require.Equal(t, `{"content":[{"type":"text","text":"hi"}]}`, got)
	require.Equal(t, got, tctx.BodyCapture.ResponseBody(),
		"the capture is a copy of exactly what the client received")
	require.False(t, tctx.BodyCapture.ResponseBodyTruncated())
}

func TestBodyCaptureResponse_NeverBlocksOnANeverEndingBody(t *testing.T) {
	// A reply that produces two frames and then hangs — a model that is still
	// generating, or an upstream that stalls. The client must still get those
	// two frames, and the audit copy must already hold them, while the stream is
	// open. Buffer-then-forward would deliver nothing until the hang cleared.
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })

	bc := newResponseTransform(t, 16*1024, defaultMaxResponseBodyBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"stream":true}`)
	body := newSteppedBody(hold,
		"event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"one\"}}\n\n",
		"event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"two\"}}\n\n",
	)
	resp := makeResponse(body, http.Header{"Content-Type": []string{"text/event-stream"}})
	tctx := &transform.TransformContext{}

	// 1. Installing the tee returns immediately; it never touches the body.
	installed := make(chan error, 1)
	go func() {
		_, err := bc.TransformResponse(context.Background(), tctx, req, resp)
		installed <- err
	}()
	select {
	case err := <-installed:
		require.NoError(t, err)
	case <-time.After(testDeadline):
		t.Fatal("TransformResponse blocked on a body that has not finished — it must only install a tee")
	}

	// 2. The client's reads still land while upstream is mid-stream.
	reader := transform.RequireBufferedBody(resp.Body).StreamingReader()
	buf := make([]byte, 32*1024)
	for i := 1; i <= 2; i++ {
		type readResult struct {
			n   int
			err error
		}
		done := make(chan readResult, 1)
		go func() {
			n, err := reader.Read(buf)
			done <- readResult{n, err}
		}()
		select {
		case r := <-done:
			require.NoError(t, r.err)
			require.Greater(t, r.n, 0, "client read %d returned no bytes", i)
		case <-time.After(testDeadline):
			t.Fatalf("client read %d blocked while the response body was still streaming", i)
		}

		// 3. And the audit copy is already there — mid-stream, not at EOF.
		require.Contains(t, tctx.BodyCapture.ResponseBody(),
			[]string{"\"one\"", "\"two\""}[i-1],
			"tee must capture frame %d as it passes, not after the stream ends", i)
	}

	// The stream is still open (the body is still holding), yet both frames have
	// been delivered and captured.
	require.False(t, body.wasClosed(), "the upstream body should still be open")
	require.False(t, tctx.BodyCapture.ResponseBodyTruncated())
}

func TestBodyCaptureResponse_CapTruncatesInsteadOfStalling(t *testing.T) {
	// The cap bounds the audit copy, not the client's stream. Past the cap the
	// sink drops bytes and keeps reporting success: it must never withhold room
	// as back-pressure, because that back-pressure lands on the client.
	const capBytes = 100
	const chunk = 512
	const chunks = 40 // 20 KiB total, 200x the cap

	bc := newResponseTransform(t, 16*1024, capBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)

	pieces := make([]string, chunks)
	for i := range pieces {
		pieces[i] = strings.Repeat("y", chunk)
	}
	// No hold: this body ends. The deadline in forwardToClient is what proves
	// the oversized stream is not stalled by the full sink.
	resp := makeResponse(newSteppedBody(nil, pieces...), nil)
	tctx := &transform.TransformContext{}

	_, err := bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)

	got := forwardToClient(t, resp)
	require.Equal(t, chunk*chunks, len(got),
		"the client must receive every byte regardless of the audit cap")

	require.Equal(t, capBytes, len(tctx.BodyCapture.ResponseBody()),
		"the audit copy must stop at exactly the cap")
	require.Equal(t, strings.Repeat("y", capBytes), tctx.BodyCapture.ResponseBody())
	require.True(t, tctx.BodyCapture.ResponseBodyTruncated(),
		"truncation must be reported, not silent")
}

func TestBodyCaptureResponse_TruncationTrimsPartialUTF8Rune(t *testing.T) {
	// Same rune-boundary care the request path takes: a cap that lands mid-rune
	// must not leave a dangling fragment that renders as U+FFFD in the audit
	// JSON. "€" is 3 bytes (0xE2 0x82 0xAC); with a body of "ab€cd" and a cap of
	// 4, the naive cut keeps "ab" plus the first 2 bytes of "€".
	const capBytes = 4
	bc := newResponseTransform(t, 16*1024, capBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)
	resp := makeResponse(io.NopCloser(strings.NewReader("ab€cd")), nil)
	tctx := &transform.TransformContext{}

	_, err := bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	require.Equal(t, "ab€cd", forwardToClient(t, resp), "the client still gets every byte")

	got := tctx.BodyCapture.ResponseBody()
	require.True(t, utf8.ValidString(got), "captured body must be valid UTF-8, got %q", got)
	require.Equal(t, "ab", got, "partial trailing rune should be trimmed back to a boundary")
	require.True(t, tctx.BodyCapture.ResponseBodyTruncated())
}

func TestBodyCaptureResponse_BinaryTailSurvivesTruncation(t *testing.T) {
	// The rune trim is bounded to UTFMax-1 bytes so a body that is genuinely not
	// UTF-8 keeps its tail rather than being progressively stripped.
	const capBytes = 8
	bc := newResponseTransform(t, 16*1024, capBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)
	binary := string([]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6})
	resp := makeResponse(io.NopCloser(strings.NewReader(binary)), nil)
	tctx := &transform.TransformContext{}

	_, err := bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	forwardToClient(t, resp)

	// 8 bytes capped, at most 3 trimmed — never the whole thing.
	require.GreaterOrEqual(t, len(tctx.BodyCapture.ResponseBody()), capBytes-(utf8.UTFMax-1))
	require.True(t, tctx.BodyCapture.ResponseBodyTruncated())
}

func TestBodyCaptureResponse_SSECapturedRawAndUnmerged(t *testing.T) {
	// Merging SSE frames or pre-parsing JSON is the log consumer's job. Doing it
	// here would mean guessing at a provider's streaming shape in the one place
	// that must stay fast and provider-agnostic, so the capture hands over the
	// concatenated raw body.
	sse := strings.Join([]string{
		"event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
		"event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"def \"}}\n\n",
		"event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"main():\"}}\n\n",
		"data: [DONE]\n\n",
	}, "")

	bc := newResponseTransform(t, 16*1024, defaultMaxResponseBodyBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"stream":true}`)
	resp := makeResponse(
		io.NopCloser(strings.NewReader(sse)),
		http.Header{"Content-Type": []string{"text/event-stream"}},
	)
	tctx := &transform.TransformContext{}

	_, err := bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	require.Equal(t, sse, forwardToClient(t, resp))

	captured := tctx.BodyCapture.ResponseBody()
	require.Equal(t, sse, captured, "SSE must be captured byte-for-byte")
	require.Contains(t, captured, "data: [DONE]", "envelope lines must survive")
	require.NotEqual(t, "def main():", captured, "the proxy must not merge the deltas itself")
}

func TestBodyCaptureResponse_NoMatch_NothingCaptured(t *testing.T) {
	bc := newResponseTransform(t, 16*1024, defaultMaxResponseBodyBytes, messagesRules())
	req := makeRequest(t, "example.com", "/anywhere", `{"x":1}`)
	resp := makeResponse(io.NopCloser(strings.NewReader("not ours")), nil)
	tctx := &transform.TransformContext{}

	res, err := bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Nil(t, tctx.BodyCapture)

	// And the body still reaches the client untouched.
	require.Equal(t, "not ours", forwardToClient(t, resp))
}

func TestBodyCaptureResponse_BodylessRequest_StillCapturesTheResponse(t *testing.T) {
	// A matching request with no body of its own leaves BodyCapture nil on the
	// request leg. The response leg has to create it, or a GET's reply would be
	// dropped on the floor.
	bc := newResponseTransform(t, 16*1024, defaultMaxResponseBodyBytes, []hostmatch.RuleConfig{{Host: "api.anthropic.com"}})
	req := httptest.NewRequest("GET", "http://api.anthropic.com/v1/models", nil)
	req.Host = "api.anthropic.com"
	req.Body = transform.NewBufferedBody(req.Body, 1024)
	resp := makeResponse(io.NopCloser(strings.NewReader(`{"data":[]}`)), nil)
	tctx := &transform.TransformContext{}

	_, err := bc.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Nil(t, tctx.BodyCapture, "no request body to capture")

	_, err = bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	require.NotNil(t, tctx.BodyCapture, "the response leg must create the capture")

	require.Equal(t, `{"data":[]}`, forwardToClient(t, resp))
	require.Equal(t, `{"data":[]}`, tctx.BodyCapture.ResponseBody())
	require.Equal(t, "", tctx.BodyCapture.RequestBody())
}

func TestBodyCaptureResponse_SharesOneCaptureWithTheRequestLeg(t *testing.T) {
	bc := newResponseTransform(t, 16*1024, defaultMaxResponseBodyBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"prompt":"hi"}`)
	resp := makeResponse(io.NopCloser(strings.NewReader("reply")), nil)
	tctx := &transform.TransformContext{}

	_, err := bc.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	first := tctx.BodyCapture

	_, err = bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	require.Same(t, first, tctx.BodyCapture, "both legs must write the same capture")

	forwardToClient(t, resp)
	require.Equal(t, `{"prompt":"hi"}`, tctx.BodyCapture.RequestBody())
	require.Equal(t, "reply", tctx.BodyCapture.ResponseBody())
}

func TestBodyCaptureResponse_GzipDecoded(t *testing.T) {
	// An upstream that honors the client's Accept-Encoding sends compressed
	// bytes. Capturing them raw would hand the log consumer binary noise, so the
	// capture decodes — but only when read, after the client already has its
	// bytes, never on the streaming path.
	const plain = `{"content":[{"type":"text","text":"compressed reply"}]}`
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, err := zw.Write([]byte(plain))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	wire := gz.String()

	bc := newResponseTransform(t, 16*1024, defaultMaxResponseBodyBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)
	resp := makeResponse(
		io.NopCloser(strings.NewReader(wire)),
		http.Header{"Content-Encoding": []string{"gzip"}},
	)
	tctx := &transform.TransformContext{}

	_, err = bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)

	require.Equal(t, wire, forwardToClient(t, resp),
		"the client must receive the compressed bytes unchanged")
	require.Equal(t, plain, tctx.BodyCapture.ResponseBody())
}

func TestBodyCaptureResponse_GzipDecodeIsBoundedByTheCap(t *testing.T) {
	// The tee's cap bounds COMPRESSED bytes, and a compression ratio is not ours
	// to pick: a few KiB of gzip can decode to megabytes. The decode is bounded
	// too, and reports the clip as truncation.
	const capBytes = 8 * 1024
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, err := zw.Write([]byte(strings.Repeat("A", 8*1024*1024))) // ~8 KiB compressed
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.Less(t, gz.Len(), capBytes, "the compressed form must fit under the cap for this test to mean anything")

	bc := newResponseTransform(t, 16*1024, capBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)
	resp := makeResponse(
		io.NopCloser(bytes.NewReader(gz.Bytes())),
		http.Header{"Content-Encoding": []string{"gzip"}},
	)
	tctx := &transform.TransformContext{}

	_, err = bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	forwardToClient(t, resp)

	require.Equal(t, capBytes, len(tctx.BodyCapture.ResponseBody()),
		"the decoded copy must be bounded by the cap, not by the compression ratio")
	require.True(t, tctx.BodyCapture.ResponseBodyTruncated())
}

func TestBodyCaptureResponse_TruncatedFlagAgreesWhicheverAccessorRunsFirst(t *testing.T) {
	// The emitters call ResponseBody() then ResponseBodyTruncated(); nothing
	// should depend on that order, since decode-side clipping is discovered
	// during the decode.
	const capBytes = 512
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, err := zw.Write([]byte(strings.Repeat("B", 1024*1024)))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	bc := newResponseTransform(t, 16*1024, capBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)
	resp := makeResponse(
		io.NopCloser(bytes.NewReader(gz.Bytes())),
		http.Header{"Content-Encoding": []string{"gzip"}},
	)
	tctx := &transform.TransformContext{}

	_, err = bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	forwardToClient(t, resp)

	// Truncated first, body second — the reverse of the emitters' order.
	require.True(t, tctx.BodyCapture.ResponseBodyTruncated())
	require.Equal(t, capBytes, len(tctx.BodyCapture.ResponseBody()))
}

func TestBodyCaptureResponse_UnsupportedEncodingSkippedAndAnnotated(t *testing.T) {
	// brotli/zstd: capturing bytes nothing downstream can decode would burn the
	// audit byte budget on noise. Skip, and say so on the trace so the gap is
	// visible rather than looking like an empty reply.
	bc := newResponseTransform(t, 16*1024, defaultMaxResponseBodyBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)
	resp := makeResponse(
		io.NopCloser(strings.NewReader("\x1b brotli bytes")),
		http.Header{"Content-Encoding": []string{"br"}},
	)
	tctx := &transform.TransformContext{}

	_, err := bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)

	require.Equal(t, "\x1b brotli bytes", forwardToClient(t, resp))
	if tctx.BodyCapture != nil {
		require.Equal(t, "", tctx.BodyCapture.ResponseBody())
	}
	require.Equal(t, "br", tctx.DrainAnnotations()["response_body_encoding_unsupported"])
}

func TestBodyCaptureResponse_ClientDisconnectKeepsThePartialCopy(t *testing.T) {
	// The client gives up mid-reply. Whatever already streamed is still valid
	// audit data; the capture must not be all-or-nothing.
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })

	bc := newResponseTransform(t, 16*1024, defaultMaxResponseBodyBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)
	resp := makeResponse(newSteppedBody(hold, "data: partial\n\n"), nil)
	tctx := &transform.TransformContext{}

	_, err := bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)

	reader := transform.RequireBufferedBody(resp.Body).StreamingReader()
	buf := make([]byte, 4096)
	n, err := reader.Read(buf)
	require.NoError(t, err)
	require.Greater(t, n, 0)
	// ...and the client walks away without reading the rest.

	require.Equal(t, "data: partial\n\n", tctx.BodyCapture.ResponseBody())
	require.False(t, tctx.BodyCapture.ResponseBodyTruncated(),
		"a short read is not a cap truncation")
}

func TestBodyCaptureResponse_NoResponseBody(t *testing.T) {
	bc := newResponseTransform(t, 16*1024, defaultMaxResponseBodyBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)
	resp := &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{}, Body: http.NoBody}
	tctx := &transform.TransformContext{}

	res, err := bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Nil(t, tctx.BodyCapture)
}

func TestBodyCaptureResponse_NonBufferedBodySkippedNotPanicked(t *testing.T) {
	// A transform ahead of this one can hand back a plain body. That is an audit
	// concern, not a request-killing one — RequireBufferedBody would panic.
	bc := newResponseTransform(t, 16*1024, defaultMaxResponseBodyBytes, messagesRules())
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("plain body")),
	}
	tctx := &transform.TransformContext{}

	require.NotPanics(t, func() {
		res, err := bc.TransformResponse(context.Background(), tctx, req, resp)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, res.Action)
	})
	require.Contains(t, tctx.DrainAnnotations(), "response_body_capture_skipped")
}

// --- config -----------------------------------------------------------------

func factoryFromYAML(t *testing.T, doc string) *bodyCapture {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(doc), &node))
	// yaml.Unmarshal gives a document node; the factory expects the mapping.
	require.NotEmpty(t, node.Content)
	tr, err := factory(*node.Content[0], nil)
	require.NoError(t, err)
	bc, ok := tr.(*bodyCapture)
	require.True(t, ok)
	return bc
}

func TestBodyCaptureConfig_ResponseCaptureIsOffUnlessAskedFor(t *testing.T) {
	// The compatibility guarantee: a config written before this feature existed
	// keeps its exact previous behavior.
	bc := factoryFromYAML(t, `
max_request_body_bytes: 16384
rules:
  - host: "api.anthropic.com"
`)
	require.False(t, bc.captureResponseBody)

	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)
	resp := makeResponse(io.NopCloser(strings.NewReader("reply")), nil)
	tctx := &transform.TransformContext{}

	_, err := bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	require.Equal(t, -1, transform.RequireBufferedBody(resp.Body).Len(),
		"the default must not so much as install a tee")
	require.Nil(t, tctx.BodyCapture)
}

func TestBodyCaptureConfig_ExplicitCapsAreHonored(t *testing.T) {
	bc := factoryFromYAML(t, `
max_request_body_bytes: 16384
capture_response_body: true
max_response_body_bytes: 65536
rules:
  - host: "api.anthropic.com"
    methods: ["POST"]
    paths: ["/v1/messages", "/v1/complete"]
`)
	require.Equal(t, int64(16384), bc.maxRequestBodyBytes)
	require.True(t, bc.captureResponseBody)
	require.Equal(t, int64(65536), bc.maxResponseBodyBytes)
	require.Len(t, bc.rules, 1)
}

func TestBodyCaptureConfig_DefaultsWhenUnset(t *testing.T) {
	bc := factoryFromYAML(t, `
capture_response_body: true
rules:
  - host: "api.openai.com"
`)
	require.Equal(t, int64(defaultMaxRequestBodyBytes), bc.maxRequestBodyBytes)
	require.Equal(t, int64(defaultMaxResponseBodyBytes), bc.maxResponseBodyBytes)
}

func TestBodyCaptureConfig_ResponseCapReachesTheCapture(t *testing.T) {
	// The configured cap has to arrive on the per-request capture, not just sit
	// on the transform. A zero here would mean capturing nothing at all.
	bc := factoryFromYAML(t, `
capture_response_body: true
max_response_body_bytes: 8
rules:
  - host: "api.anthropic.com"
`)
	req := makeRequest(t, "api.anthropic.com", "/v1/messages", `{"x":1}`)
	resp := makeResponse(io.NopCloser(strings.NewReader("0123456789abcdef")), nil)
	tctx := &transform.TransformContext{}

	_, err := bc.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	require.Equal(t, "0123456789abcdef", forwardToClient(t, resp))
	require.Equal(t, "01234567", tctx.BodyCapture.ResponseBody())
	require.True(t, tctx.BodyCapture.ResponseBodyTruncated())
}
