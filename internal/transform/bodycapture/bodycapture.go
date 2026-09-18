// Package bodycapture implements a transform that captures the request bodies
// of matching requests - and, when explicitly enabled, their response bodies -
// and exposes them via PipelineResult.BodyCapture for the audit emitters to
// render as a `body_capture` group holding `request_body`,
// `request_body_truncated`, `response_body` and `response_body_truncated`.
//
// The two halves are captured by different mechanisms, and the difference is
// the whole design:
//
//   - A REQUEST is already fully in hand before it can go upstream, so it is
//     read via BufferedBody and copied.
//   - A RESPONSE is TEE'D, never buffered-then-forwarded. Model replies stream:
//     an Anthropic or OpenAI SSE reply trickles for as long as the model talks.
//     Buffering a reply in order to copy it would hold the client's bytes
//     hostage for the length of the stream, which is a visible hang; missing
//     the audit signal is strictly better than that. So the copy rides
//     BufferedBody.TeeTo, the client's own reads drive it, and bytes past the
//     cap are DROPPED rather than queued - dropping cannot apply back-pressure,
//     queueing can.
//
// What lands in `response_body` is the raw reply as it went over the wire, only
// content-decoded (gzip/deflate) when the upstream compressed it. SSE frames
// are NOT merged and JSON is NOT parsed here: the consumer of these records
// does that, and doing it in the proxy would mean guessing at a provider's
// streaming shape in the one place that must never slow down.
//
// Response capture is off by default. Set `capture_response_body: true` to turn
// it on.
package bodycapture

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("body_capture", factory)
}

// defaultMaxRequestBodyBytes is the per-request cap when the config doesn't
// specify max_request_body_bytes. Sized for typical AI-prompt capture — a
// well-structured chat completion request is comfortably under 16 KB. Long
// conversation histories may truncate; the truncation flag in the audit
// surface lets downstream consumers see when this happens.
const defaultMaxRequestBodyBytes = 16 * 1024

// defaultMaxResponseBodyBytes is the per-response cap when response capture is
// enabled without specifying max_response_body_bytes. Larger than the request
// cap because a reply is the payload a consumer actually reads, while a request
// is context — and because an SSE reply spends most of its bytes on frame
// envelopes rather than text. Deployments should set the key explicitly rather
// than inherit this; the excess past the cap is dropped as it streams by, never
// queued.
const defaultMaxResponseBodyBytes = 64 * 1024

// bodyCapture is the transform itself. Unexported because all external use
// goes through the factory registration.
type bodyCapture struct {
	rules                []hostmatch.Rule
	maxRequestBodyBytes  int64
	captureResponseBody  bool
	maxResponseBodyBytes int64
}

type config struct {
	MaxRequestBodyBytes  int64                  `yaml:"max_request_body_bytes"`
	CaptureResponseBody  bool                   `yaml:"capture_response_body"`
	MaxResponseBodyBytes int64                  `yaml:"max_response_body_bytes"`
	Rules                []hostmatch.RuleConfig `yaml:"rules"`
}

func factory(cfg yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing body_capture config: %w", err)
	}
	rules, err := hostmatch.CompileRules(c.Rules, "body_capture")
	if err != nil {
		return nil, err
	}
	maxReq := c.MaxRequestBodyBytes
	if maxReq <= 0 {
		maxReq = defaultMaxRequestBodyBytes
	}
	maxResp := c.MaxResponseBodyBytes
	if maxResp <= 0 {
		maxResp = defaultMaxResponseBodyBytes
	}
	return &bodyCapture{
		rules:                rules,
		maxRequestBodyBytes:  maxReq,
		captureResponseBody:  c.CaptureResponseBody,
		maxResponseBodyBytes: maxResp,
	}, nil
}

// Name returns the transform's registered name.
func (b *bodyCapture) Name() string { return "body_capture" }

// TransformRequest reads the request body via the pipeline's BufferedBody and,
// if the request matches a configured rule, attaches the captured (and
// possibly truncated) body bytes to TransformContext.BodyCapture. The proxy
// copies that onto PipelineResult after the pipeline returns; the audit
// emitters render it as a `body_capture` group with `request_body` +
// `request_body_truncated`. On a successful capture the transform also
// annotates its own trace entry with `captured_bytes` and `truncated` markers
// so the request_transforms array self-documents.
//
// Always returns ActionContinue — body_capture is observation-only and never
// rejects a request. Read errors are annotated for observability and swallowed
// so a misbehaving body reader can't take down the request.
func (b *bodyCapture) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	cont := &transform.TransformResult{Action: transform.ActionContinue}
	if !hostmatch.MatchAnyRule(b.rules, req) {
		return cont, nil
	}
	if req.Body == nil || req.Body == http.NoBody {
		return cont, nil
	}
	bb := transform.RequireBufferedBody(req.Body)
	data, err := io.ReadAll(bb)
	if err != nil {
		tctx.Annotate("body_capture_error", err.Error())
		return cont, nil
	}
	if len(data) == 0 {
		return cont, nil
	}
	truncated := false
	if int64(len(data)) > b.maxRequestBodyBytes {
		data = trimPartialRune(data[:b.maxRequestBodyBytes])
		truncated = true
	}
	b.captureFor(tctx).setRequest(string(data), truncated)
	// Lightweight markers on the transform's own trace entry so the
	// request_transforms array self-documents that a body was captured. The
	// body itself is not duplicated here — it lives in the top-level
	// body_capture group, which is cheaper for log consumers to query.
	tctx.Annotate("captured_bytes", len(data))
	tctx.Annotate("truncated", truncated)
	return cont, nil
}

// TransformResponse arranges for the response body to be TEE'D into the audit
// capture as it streams to the client. It does not read, buffer, or delay the
// body: installing the tee is O(1), and the client's own reads drive the copy
// (see transform.BufferedBody.TeeTo). A reply that trickles for two minutes is
// forwarded byte-for-byte as it arrives, and the capture simply holds whatever
// went past by the time the audit record is emitted — which the proxy defers
// until after the body has been written to the client.
//
// A no-op unless `capture_response_body: true`, so an existing configuration
// sees exactly the behavior it saw before.
//
// Always returns ActionContinue: body_capture is observation-only and never
// rejects or rewrites a response. A response whose Content-Encoding this
// transform cannot decode is deliberately NOT captured — see decodable — since
// shipping undecodable bytes into the audit log spends the byte budget on
// something no consumer can read.
func (b *bodyCapture) TransformResponse(_ context.Context, tctx *transform.TransformContext, req *http.Request, resp *http.Response) (*transform.TransformResult, error) {
	cont := &transform.TransformResult{Action: transform.ActionContinue}
	if !b.captureResponseBody {
		return cont, nil
	}
	if !hostmatch.MatchAnyRule(b.rules, req) {
		return cont, nil
	}
	if resp == nil || resp.Body == nil || resp.Body == http.NoBody {
		return cont, nil
	}
	enc := normalizeEncoding(resp.Header.Get("Content-Encoding"))
	if !decodable(enc) {
		// br / zstd / a chain of encodings. Annotate so the gap is visible on
		// the audit trace instead of silently reading as "the upstream said
		// nothing".
		tctx.Annotate("response_body_encoding_unsupported", enc)
		return cont, nil
	}
	bb, ok := resp.Body.(*transform.BufferedBody)
	if !ok {
		// A transform ahead of this one replaced the body with something that
		// isn't a BufferedBody. Nothing to tee off; don't panic over an audit
		// concern the way RequireBufferedBody would.
		tctx.Annotate("response_body_capture_skipped", fmt.Sprintf("%T", resp.Body))
		return cont, nil
	}
	c := b.captureFor(tctx)
	c.armResponse(enc)
	bb.TeeTo(c)
	return cont, nil
}

// captureFor returns the per-request capture, creating and installing it on the
// TransformContext the first time either leg needs it. The request leg usually
// creates it, but a matching request with no body (or one whose body failed to
// read) leaves it nil, and the response leg still has something worth keeping.
func (b *bodyCapture) captureFor(tctx *transform.TransformContext) *capture {
	if existing, ok := tctx.BodyCapture.(*capture); ok && existing != nil {
		return existing
	}
	c := &capture{maxResponseBodyBytes: b.maxResponseBodyBytes}
	tctx.BodyCapture = c
	return c
}

// capture is the concrete implementation of transform.BodyCapture. One per
// request. The response half is written by whichever goroutine streams the
// response body and read by the audit callback, so every field goes through the
// mutex — the two are the same goroutine in today's proxy, but an audit sink
// that ever moves off it must not turn into a data race.
type capture struct {
	mu                   sync.Mutex
	requestBody          string
	requestBodyTruncated bool
	responseEncoding     string
	maxResponseBodyBytes int64
	responseRaw          []byte
	responseTruncated    bool
	responseDecoded      string
	responseDecodedValid bool
}

func (c *capture) setRequest(body string, truncated bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requestBody = body
	c.requestBodyTruncated = truncated
}

// armResponse records that a tee is about to be installed, along with the
// content encoding the captured bytes will be in.
func (c *capture) armResponse(encoding string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.responseEncoding = encoding
	c.responseRaw = nil
	c.responseTruncated = false
	c.responseDecoded = ""
	c.responseDecodedValid = false
}

// Write implements io.Writer as the tee sink for the response body.
//
// It is bounded and NON-BLOCKING BY CONSTRUCTION. Bytes past the cap are
// dropped and the write still reports full success, because this Write sits
// inline on the client's read path: anything it waited for — a lock held
// elsewhere, a channel, a flush, room in a queue — the client would wait for
// too. Reporting a short write or an error would be just as bad, since a strict
// tee would surface it as a read error on the client's stream.
func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.responseDecoded = ""
	c.responseDecodedValid = false
	room := c.maxResponseBodyBytes - int64(len(c.responseRaw))
	switch {
	case room <= 0:
		c.responseTruncated = true
	case int64(len(p)) > room:
		c.responseRaw = append(c.responseRaw, p[:room]...)
		c.responseTruncated = true
	default:
		c.responseRaw = append(c.responseRaw, p...)
	}
	return len(p), nil
}

func (c *capture) RequestBody() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requestBody
}

func (c *capture) RequestBodyTruncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requestBodyTruncated
}

// ResponseBody returns the tee'd bytes, content-decoded if needed. Decoding
// happens here rather than in Write so the client's read path never pays for
// it: by the time anything calls this, the response has already been forwarded.
func (c *capture) ResponseBody() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decodeLocked()
	return c.responseDecoded
}

// ResponseBodyTruncated reports whether the capture lost the tail of the reply —
// either because the wire bytes hit the cap, or because decoding a compressed
// reply hit it. For SSE a truncated capture simply loses its trailing frames.
func (c *capture) ResponseBodyTruncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decodeLocked()
	return c.responseTruncated
}

// decodeLocked memoizes the decoded body and folds any decode-side truncation
// into responseTruncated, so the two accessors agree no matter which is called
// first. Caller holds c.mu.
func (c *capture) decodeLocked() {
	if c.responseDecodedValid {
		return
	}
	decoded, clipped := decodeBody(c.responseRaw, c.responseEncoding, c.maxResponseBodyBytes)
	if clipped {
		c.responseTruncated = true
	}
	if c.responseTruncated {
		decoded = trimPartialRune(decoded)
	}
	c.responseDecoded = string(decoded)
	c.responseDecodedValid = true
}

// trimPartialRune drops a dangling multi-byte UTF-8 fragment from the end of a
// body that was cut at a byte boundary, which would otherwise render as U+FFFD
// in the audit JSON. Bounded to UTFMax-1 bytes so a body that is genuinely not
// UTF-8 (binary) keeps its tail rather than being progressively stripped.
func trimPartialRune(data []byte) []byte {
	for i := 0; i < utf8.UTFMax-1 && len(data) > 0; i++ {
		if r, size := utf8.DecodeLastRune(data); r != utf8.RuneError || size > 1 {
			break
		}
		data = data[:len(data)-1]
	}
	return data
}

// normalizeEncoding lowercases and trims a Content-Encoding header value.
func normalizeEncoding(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

// decodable reports whether decodeBody can turn bytes in this encoding back
// into text. Anything else (br, zstd, or a comma-separated chain) is not
// captured at all.
func decodable(enc string) bool {
	switch enc {
	case "", "identity", "gzip", "x-gzip", "deflate":
		return true
	default:
		return false
	}
}

// decodeBody content-decodes captured wire bytes, returning the decoded body and
// whether the decode was clipped by max.
//
// A truncated input stream is expected and normal — the tee's cap cuts it
// mid-stream — so a decode error after some output has been produced keeps that
// output rather than discarding the reply.
//
// max also bounds the OUTPUT, which is the point: the cap on the tee bounds the
// compressed bytes, and a compression ratio is not something this process gets
// to choose. Without an output bound, a small stream that expands enormously
// would size the audit copy for us.
func decodeBody(data []byte, enc string, max int64) ([]byte, bool) {
	if len(data) == 0 {
		return nil, false
	}
	switch enc {
	case "", "identity":
		return data, false
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false
		}
		// Close errors are ignored throughout: these readers wrap an in-memory
		// slice, and a checksum complaint on the deliberately truncated tail is
		// expected rather than informative.
		defer func() { _ = zr.Close() }()
		return readAllBounded(zr, max)
	case "deflate":
		// RFC 9110 "deflate" is zlib-wrapped, but raw deflate is common enough
		// in the wild that it is worth the second attempt.
		if zr, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
			defer func() { _ = zr.Close() }()
			if out, clipped := readAllBounded(zr, max); len(out) > 0 {
				return out, clipped
			}
		}
		fr := flate.NewReader(bytes.NewReader(data))
		defer func() { _ = fr.Close() }()
		return readAllBounded(fr, max)
	default:
		return nil, false
	}
}

// readAllBounded reads at most max bytes from r, reporting whether there was
// more. A max of 0 or less means unbounded.
func readAllBounded(r io.Reader, max int64) ([]byte, bool) {
	if max <= 0 {
		out, _ := io.ReadAll(r)
		return out, false
	}
	// Read one byte past the cap so hitting it exactly is distinguishable from
	// overflowing it.
	out, _ := io.ReadAll(io.LimitReader(r, max+1))
	if int64(len(out)) > max {
		return out[:max], true
	}
	return out, false
}
