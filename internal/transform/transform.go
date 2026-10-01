// Package transform defines the Transformer interface and pipeline execution
// for iron-proxy's request/response transform system.
package transform

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net/http"
	"time"
)

// TransformAction controls what happens after a transform runs.
type TransformAction int

const (
	// ActionContinue passes the request to the next transform (or upstream).
	ActionContinue TransformAction = iota

	// ActionReject stops the pipeline and returns TransformResult.Response to the client.
	// If Response is nil, the proxy returns a default 403 Forbidden.
	// Use this when the proxy is denying the request on the client's behalf.
	ActionReject

	// ActionStub stops the pipeline and returns TransformResult.Response to
	// the client, the same way ActionReject does. Unlike ActionReject, it
	// signals that the proxy is intentionally serving a synthetic response
	// (e.g. a stubbed OAuth2 token endpoint) rather than denying the request.
	// Audit logs render this as "stub" and log at INFO so operators can find
	// proxy-served responses without conflating them with rejections.
	// If Response is nil, the proxy falls back to a default 403 Forbidden,
	// the same as ActionReject.
	ActionStub
)

// ShortCircuitAction returns the action of the trace that short-circuited the
// pipeline (ActionReject or ActionStub), or ActionContinue if none did. The
// short-circuiting transform is always the last appended trace because the
// pipeline returns immediately after appending it.
func ShortCircuitAction(traces []TransformTrace) TransformAction {
	if n := len(traces); n > 0 {
		switch traces[n-1].Action {
		case ActionReject, ActionStub:
			return traces[n-1].Action
		}
	}
	return ActionContinue
}

// Mode identifies how the proxy obtained the request being transformed.
type Mode int

const (
	// ModeMITM means the request was parsed from a terminated TLS connection
	// (or plaintext HTTP) and has full method, path, headers, and body.
	ModeMITM Mode = iota

	// ModeSNIOnly means the request is a synthetic host-only stand-in built
	// from a peeked TLS ClientHello SNI. Method, path, headers, and body are
	// all empty; transforms that depend on them cannot function.
	ModeSNIOnly
)

// String returns the canonical string form of the mode.
func (m Mode) String() string {
	switch m {
	case ModeMITM:
		return "mitm"
	case ModeSNIOnly:
		return "sni-only"
	default:
		return "unknown"
	}
}

// TransformContext carries metadata about the connection and request.
type TransformContext struct {
	SNI        string
	ClientCert *x509.Certificate
	Logger     *slog.Logger
	Mode       Mode
	Tunnel     *TunnelInfo

	// BodyCapture is the side channel a body_capture transform uses to
	// communicate captured request body bytes out of the pipeline. The proxy
	// copies it onto PipelineResult after the request pipeline runs so the
	// audit emitters can render a `body_capture` group with `request_body` /
	// `request_body_truncated`. nil when no body_capture rule matched.
	BodyCapture BodyCapture

	// annotations is written by transforms via Annotate and read by the pipeline
	// to build TransformTrace. Not exported — transforms use the Annotate method.
	annotations map[string]any
}

// TunnelInfo carries metadata from the CONNECT/SOCKS5 tunnel that established
// an inner request.
type TunnelInfo struct {
	// Target is the host:port from the CONNECT request or SOCKS5 target.
	Target string

	// RequestTransforms are the traces from the CONNECT/SOCKS5 request
	// pipeline, in the order the transforms ran. Inner request transforms and
	// audit consume this to attribute tunnel-level annotations to the
	// transform that produced them.
	RequestTransforms []TransformTrace

	// Credential is the Proxy-Authorization value presented on the CONNECT,
	// kept so per-request policy can re-check it. Never serialized: TunnelInfo
	// reaches audit output.
	Credential string `json:"-"`
}

// Annotate attaches audit metadata to the current transform's trace.
// Values must be JSON-serializable. Never put actual secret values here.
func (tctx *TransformContext) Annotate(key string, value any) {
	if tctx.annotations == nil {
		tctx.annotations = make(map[string]any)
	}
	tctx.annotations[key] = value
}

// drainAnnotations returns and clears the current annotations.
func (tctx *TransformContext) DrainAnnotations() map[string]any {
	a := tctx.annotations
	tctx.annotations = nil
	return a
}

// PipelineResult captures the full outcome of a request passing through the pipeline.
type PipelineResult struct {
	Host       string
	Method     string
	Path       string
	RemoteAddr string
	SNI        string
	Mode       Mode

	StartedAt time.Time
	Duration  time.Duration

	Action     TransformAction
	StatusCode int

	Tunnel *TunnelInfo

	RequestTransforms  []TransformTrace
	ResponseTransforms []TransformTrace

	// MCP carries audit data from the MCP policy interceptor when the
	// request matched a configured server. nil otherwise. Populated and
	// consumed by the proxy and rendered by the audit functions; the
	// transform package treats it as opaque to avoid an import cycle with
	// internal/mcp.
	MCP MCPAudit

	// BodyCapture carries captured request body bytes from a body_capture
	// transform when the request matched a configured rule. nil otherwise.
	// Populated by the proxy by copying tctx.BodyCapture after the request
	// pipeline runs; rendered by the audit functions as a `body_capture`
	// group with `request_body` and `request_body_truncated`. The transform
	// package treats the concrete type as opaque to avoid an import cycle
	// with internal/transform/bodycapture.
	BodyCapture BodyCapture

	Err error

	// ClientCanceled distinguishes client-initiated disconnect from a real
	// failure so audit dashboards don't see phantom upstream errors.
	ClientCanceled bool
}

// MCPAudit is the read-only view of the MCP interceptor's per-request audit
// trace. The interface decouples internal/transform's audit renderers from
// the concrete *mcp.Trace type so we can render its data without importing
// the mcp package.
type MCPAudit interface {
	// MCPServer returns the matched server name, or "" when nothing matched.
	MCPServer() string
	// MCPMessages returns the audit messages in observed order. Each entry
	// is a flat key/value map suitable for JSON encoding (string-keyed).
	MCPMessages() []map[string]any
	// MCPGateway returns gateway route metadata, or nil when no gateway route
	// was applied.
	MCPGateway() map[string]any
}

// BodyCapture is the read-only view of a body_capture transform's per-request
// captured body data. The interface decouples internal/transform's audit
// renderers from the concrete struct in internal/transform/bodycapture so the
// audit emitters can render captured bodies without an import cycle.
//
// This interface covers request bodies only.
type BodyCapture interface {
	// RequestBody returns the captured request body bytes (truncated to the
	// transform's configured cap). Empty string when no rule matched the
	// request or the request had no body.
	RequestBody() string
	// RequestBodyTruncated reports whether the captured RequestBody was
	// truncated to fit the transform's configured cap.
	RequestBodyTruncated() bool
}

// TransformTrace records what a single transform did.
type TransformTrace struct {
	Name        string
	Action      TransformAction
	Duration    time.Duration
	Err         error
	Annotations map[string]any
}

// TransformResult controls what happens after a transform runs.
type TransformResult struct {
	Action   TransformAction
	Response *http.Response
}

// Transformer processes HTTP requests and responses.
// A single Transformer instance may be called concurrently from multiple goroutines.
type Transformer interface {
	// Name returns a human-readable name for logging and metrics.
	Name() string

	// TransformRequest is called before the request is sent upstream.
	// The transform may modify the request in place.
	// Returning ActionReject or ActionStub stops the pipeline.
	TransformRequest(ctx context.Context, tctx *TransformContext, req *http.Request) (*TransformResult, error)

	// TransformResponse is called after the response is received from upstream.
	// The transform may modify the response in place.
	// Returning ActionReject or ActionStub replaces the upstream response with TransformResult.Response.
	TransformResponse(ctx context.Context, tctx *TransformContext, req *http.Request, resp *http.Response) (*TransformResult, error)
}
