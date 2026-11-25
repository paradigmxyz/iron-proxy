// Package proxy implements the iron-proxy HTTP/HTTPS proxy. The HTTPS
// listener supports two modes: MITM (default), which terminates TLS using a
// CA-signed leaf cert, and SNI-only, which peeks the ClientHello SNI and
// TCP-passthroughs to the upstream without terminating TLS.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/ironsh/iron-proxy/internal/tenancy"
	"github.com/ironsh/iron-proxy/internal/tenant"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/mcp"
	"github.com/ironsh/iron-proxy/internal/mcpgateway"
	"github.com/ironsh/iron-proxy/internal/responseretry"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// Proxy is the HTTP/HTTPS proxy server. When Mode is TLSModeMITM, the HTTPS
// listener terminates TLS using certCache; when Mode is TLSModeSNIOnly, the
// listener peeks the SNI from the ClientHello and TCP-passthroughs to the
// upstream without terminating TLS.
type Proxy struct {
	httpServer           *http.Server
	httpsServer          *http.Server
	httpsAddr            string
	tlsMode              string
	tlsListener          net.Listener
	tunnelAddr           string
	tunnelListener       net.Listener
	tunnelDone           chan struct{}
	certCache            *certcache.Cache
	pipeline             *transform.PipelineHolder
	transport            *http.Transport
	resolver             *net.Resolver
	guard                *dnsguard.Guard
	mcpPolicy            *mcp.PolicyHolder
	mcpGateway           *mcpgateway.Holder
	responseRetryHandler *responseretry.Handler
	logger               *slog.Logger
	// tenancy is set in tenancy mode: every request must belong to a tenant
	// bound by its tunnel's tenant token.
	tenancy *tenancy.Cache

	// shutdownCtx is canceled by Shutdown to unblock in-flight TCP-passthrough
	// connections that would otherwise sit on blocking Reads.
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	// sniUpstreamPort is the port dialed for SNI-only passthrough. Fixed at
	// 443 in production so a client-supplied CONNECT port cannot pivot an
	// allowlisted hostname onto a different port. Overridable in tests.
	sniUpstreamPort string
	ready           func() bool
}

const notReadyMessage = "proxy is not ready: awaiting control-plane config"

// Options configures Proxy construction.
type Options struct {
	HTTPAddr   string
	HTTPSAddr  string
	TunnelAddr string
	TLSMode    string
	CertCache  *certcache.Cache // required when TLSMode == config.TLSModeMITM
	Pipeline   *transform.PipelineHolder
	Resolver   *net.Resolver
	Guard      *dnsguard.Guard   // nil is treated as an empty (no-op) guard
	MCPPolicy  *mcp.PolicyHolder // optional MCP-aware policy interceptor; nil disables MCP handling
	MCPGateway *mcpgateway.Holder
	// ResponseRetryHandler may add headers and replay the exact transformed
	// request once after selected upstream response statuses.
	ResponseRetryHandler *responseretry.Handler
	Logger               *slog.Logger
	// UpstreamResponseHeaderTimeout overrides the upstream HTTP transport's
	// ResponseHeaderTimeout. Zero falls back to
	// config.DefaultUpstreamResponseHeaderTimeout.
	UpstreamResponseHeaderTimeout time.Duration
	// UpstreamProxy, when non-nil, routes upstream HTTP/HTTPS requests through
	// an upstream SOCKS5/HTTP CONNECT proxy (see http.Transport.Proxy). nil
	// means connect directly. Use config.UpstreamProxy.ProxyFunc to build one.
	UpstreamProxy func(*http.Request) (*url.URL, error)
	// Tenancy, when non-nil, enables tenancy mode: each CONNECT must carry a
	// tenant token, and the tunnel's requests run through that tenant's
	// pipeline instead of Pipeline. Requests without a tenant are refused.
	Tenancy *tenancy.Cache
	// Ready, when non-nil, gates request handling: while it returns false
	// every proxied request is rejected with 503. Managed proxies use it to
	// fail closed until the first control-plane config has been applied, so
	// requests can never pass through un-transformed (leaking placeholder
	// credentials upstream) during startup.
	Ready func() bool
}

// New creates a new Proxy. In TLSModeMITM, certCache must be non-nil. In
// TLSModeSNIOnly, certCache is unused and may be nil.
func New(opts Options) *Proxy {
	if opts.TLSMode == "" {
		opts.TLSMode = config.TLSModeMITM
	}
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	guard := opts.Guard
	if guard == nil {
		guard, _ = dnsguard.New(nil)
	}
	p := &Proxy{
		ready:                opts.Ready,
		httpsAddr:            opts.HTTPSAddr,
		tlsMode:              opts.TLSMode,
		tunnelAddr:           opts.TunnelAddr,
		tunnelDone:           make(chan struct{}),
		certCache:            opts.CertCache,
		pipeline:             opts.Pipeline,
		transport:            buildTransport(opts.Resolver, guard, opts.UpstreamResponseHeaderTimeout, opts.UpstreamProxy),
		resolver:             opts.Resolver,
		guard:                guard,
		mcpPolicy:            opts.MCPPolicy,
		mcpGateway:           opts.MCPGateway,
		responseRetryHandler: opts.ResponseRetryHandler,
		logger:               opts.Logger,
		tenancy:              opts.Tenancy,
		shutdownCtx:          shutdownCtx,
		shutdownCancel:       shutdownCancel,
	}

	p.httpServer = &http.Server{
		Addr:    opts.HTTPAddr,
		Handler: http.HandlerFunc(p.handleDirectHTTP),
	}

	p.httpsServer = &http.Server{
		Addr:      opts.HTTPSAddr,
		Handler:   http.HandlerFunc(p.handleDirectHTTP),
		Protocols: new(http.Protocols),
		TLSConfig: &tls.Config{
			GetCertificate: p.getCertificate,
			NextProtos:     []string{"h2", "http/1.1"},
		},
	}
	p.httpsServer.Protocols.SetHTTP1(true)
	p.httpsServer.Protocols.SetHTTP2(true)

	return p
}

// ListenAndServe starts the HTTP, HTTPS, and (optionally) tunnel listeners.
// It blocks until any server has stopped.
func (p *Proxy) ListenAndServe() error {
	n := 2
	if p.tunnelAddr != "" {
		n = 3
	}
	errc := make(chan error, n)

	go func() {
		ln, err := net.Listen("tcp", p.httpServer.Addr)
		if err != nil {
			errc <- fmt.Errorf("http listen: %w", err)
			return
		}
		p.logger.Info("http proxy starting", slog.String("addr", ln.Addr().String()))
		errc <- fmt.Errorf("http: %w", p.httpServer.Serve(ln))
	}()

	go func() {
		if p.tlsMode == config.TLSModeSNIOnly {
			errc <- p.serveHTTPSSNI()
		} else {
			errc <- p.serveHTTPSMITM()
		}
	}()

	if p.tunnelAddr != "" {
		go func() {
			errc <- fmt.Errorf("tunnel: %w", p.listenTunnel())
		}()
	}

	return <-errc
}

// serveHTTPSMITM terminates TLS on the HTTPS listener and serves requests
// through handleHTTP with leaf certs minted by the configured CA.
func (p *Proxy) serveHTTPSMITM() error {
	ln, err := net.Listen("tcp", p.httpsAddr)
	if err != nil {
		return fmt.Errorf("https listen: %w", err)
	}
	tlsLn := tls.NewListener(ln, p.httpsServer.TLSConfig)
	p.tlsListener = tlsLn
	p.logger.Info("https proxy starting", slog.String("addr", ln.Addr().String()))
	return fmt.Errorf("https: %w", p.httpsServer.Serve(tlsLn))
}

// serveHTTPSSNI runs the HTTPS listener in sni-only mode: accepts raw TCP
// connections, peeks the ClientHello SNI, and TCP-passthroughs to upstream
// without terminating TLS.
func (p *Proxy) serveHTTPSSNI() error {
	ln, err := net.Listen("tcp", p.httpsAddr)
	if err != nil {
		return fmt.Errorf("https listen: %w", err)
	}
	p.tlsListener = ln
	p.logger.Info("https proxy starting (sni-only)", slog.String("addr", ln.Addr().String()))
	for {
		conn, err := ln.Accept()
		if err != nil {
			if p.shutdownCtx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			p.logger.Warn("https accept error", slog.String("error", err.Error()))
			continue
		}
		go p.handleSNIPassthrough(conn)
	}
}

// Shutdown gracefully stops all servers.
func (p *Proxy) Shutdown(ctx context.Context) error {
	// Cancel shutdownCtx first so any in-flight TCP-passthrough proxyBidi
	// goroutines close their connections and unblock their blocking Reads.
	p.shutdownCancel()

	errHTTP := p.httpServer.Shutdown(ctx)

	var errHTTPS error
	if p.tlsMode == config.TLSModeSNIOnly {
		if p.tlsListener != nil {
			_ = p.tlsListener.Close()
		}
	} else {
		errHTTPS = p.httpsServer.Shutdown(ctx)
	}

	// Signal tunnel accept loop to stop, then close the listener.
	close(p.tunnelDone)
	if p.tunnelListener != nil {
		p.tunnelListener.Close()
	}

	if errHTTP != nil {
		return errHTTP
	}
	return errHTTPS
}

func (p *Proxy) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if p.certCache == nil {
		return nil, fmt.Errorf("cert cache not configured")
	}
	if hello.ServerName == "" {
		return nil, fmt.Errorf("no SNI provided")
	}
	return p.certCache.GetOrCreate(hello.ServerName)
}

// beginPipelineRun snapshots the pipeline to run (the tenant's in tenancy
// mode, else the current one) and returns a finish function that computes
// Duration and emits the audit record. The caller is responsible for
// populating result.Action, StatusCode, traces, and Err before finish runs —
// typically via defer. StartedAt is set here.
func (p *Proxy) beginPipelineRun(result *transform.PipelineResult, tnt *transform.Tenant) (*transform.Pipeline, func()) {
	pl := p.pipeline.Load()
	if tnt != nil {
		pl = tnt.Pipeline
		result.Tenant = tnt.Token
	}
	result.StartedAt = time.Now()
	return pl, func() {
		result.Duration = time.Since(result.StartedAt)
		pl.EmitAudit(result)
	}
}

func (p *Proxy) isReady() bool {
	return p.ready == nil || p.ready()
}

func markNotReady(result *transform.PipelineResult) {
	result.Action = transform.ActionReject
	result.StatusCode = http.StatusServiceUnavailable
	result.RequestTransforms = append(result.RequestTransforms, transform.TransformTrace{
		Name:   "ready",
		Action: transform.ActionReject,
		Annotations: map[string]any{
			"reason": "awaiting_control_plane_config",
		},
	})
}

func notReadyResponse() *http.Response {
	return &http.Response{
		StatusCode: http.StatusServiceUnavailable,
		Status:     "503 " + http.StatusText(http.StatusServiceUnavailable),
		Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(notReadyMessage + "\n")),
	}
}

// validateRequest rejects request shapes that policy and the upstream could
// interpret differently. It returns a machine-readable reason for the audit
// trace and a client-facing message, or ("", "") when r is acceptable.
func (p *Proxy) validateRequest(r *http.Request) (reason, msg string) {
	if r.Host == "" {
		return "missing_host", "missing Host header"
	}
	// Only origin-form and absolute-form targets are supported. An opaque
	// target (e.g. "http:http://other/") leaves URL.Host empty, so policy
	// would run against the Host header while the serialized request line
	// names a different authority.
	if r.URL.Opaque != "" {
		return "unsupported_request_target", "unsupported request target"
	}
	hostOnly := hostmatch.StripPort(r.Host)
	if !hostmatch.IsCanonicalHost(hostOnly) {
		return "non_canonical_host", "host must be ASCII and must not contain a zone identifier"
	}
	// Reject paths with "." or ".." segments. Policy rules (allowlist,
	// secrets, etc.) match against the raw request path, but an upstream
	// may canonicalize "/public/../admin" to "/admin" and serve a resource
	// the rule was meant to protect. Rejecting up front avoids the gap.
	if containsDotSegments(r.URL.Path) {
		return "dot_segments", "path contains dot segments"
	}
	if r.TLS != nil && r.TLS.ServerName != hostOnly {
		p.logger.Warn("SNI/Host mismatch",
			slog.String("sni", r.TLS.ServerName),
			slog.String("host", r.Host),
		)
		return "sni_host_mismatch", "SNI and Host header mismatch"
	}
	return "", ""
}

func markInvalidRequest(result *transform.PipelineResult, reason string) {
	result.Action = transform.ActionReject
	result.StatusCode = http.StatusBadRequest
	result.RequestTransforms = append(result.RequestTransforms, transform.TransformTrace{
		Name:   "request_validation",
		Action: transform.ActionReject,
		Annotations: map[string]any{
			"reason": reason,
		},
	})
}

func (p *Proxy) handleDirectHTTP(w http.ResponseWriter, r *http.Request) {
	p.handleHTTP(w, r, nil, nil)
}

// handleHTTP is the core HTTP request handler. tunnelInfo is non-nil only
// when r originated inside a CONNECT/SOCKS5 tunnel. tnt is the tenant the
// request belongs to in tenancy mode.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request, tunnelInfo *transform.TunnelInfo, tnt *transform.Tenant) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	host := r.Host

	// Clone tunnelInfo so a transform that mutates the annotations map can't
	// leak state into sibling requests that share the same tunnel.
	tctx := &transform.TransformContext{
		Logger: p.logger,
		Mode:   transform.ModeMITM,
		Tunnel: cloneTunnelInfo(tunnelInfo),
	}
	if r.TLS != nil {
		tctx.SNI = r.TLS.ServerName
	}

	result := &transform.PipelineResult{
		Host:       r.Host,
		Method:     r.Method,
		Path:       r.URL.Path,
		RemoteAddr: r.RemoteAddr,
		SNI:        tctx.SNI,
		Mode:       transform.ModeMITM,
		Tunnel:     tctx.Tunnel,
	}
	// In tenancy mode every request must belong to a tenant, and each
	// request inside a tunnel resolves its tenant again: refreshed configs,
	// control-plane refusals, invalidations and expiry take effect on the
	// tunnel's next request.
	var tenancyRej *tenancy.Rejection
	var tenantToken *tenant.Token
	if p.tenancy != nil {
		if tnt == nil {
			tenancyRej = tenancyMissing
		} else {
			tenantToken = tnt.Token
			current, rej := p.tenancy.Resolve(r.Context(), tnt.Token)
			tnt, tenancyRej = current, rej
		}
	}

	pl, finish := p.beginPipelineRun(result, tnt)
	defer finish()
	if result.Tenant == nil {
		result.Tenant = tenantToken
	}

	if reason, msg := p.validateRequest(r); reason != "" {
		markInvalidRequest(result, reason)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	if tenancyRej != nil {
		markTenancyReject(result, tenancyRej)
		writeTenancyRejection(w, tenancyRej)
		return
	}
	if tnt != nil {
		r = r.WithContext(tenant.WithToken(r.Context(), tnt.Token))
	}

	if !p.isReady() {
		markNotReady(result)
		http.Error(w, notReadyMessage, http.StatusServiceUnavailable)
		return
	}

	bodyLimits := pl.BodyLimits()
	// Wrap request body for lazy buffering by transforms.
	r.Body = transform.NewBufferedBody(r.Body, bodyLimits.MaxRequestBodyBytes)

	// Run request transforms
	rejectResp, err := pl.ProcessRequest(r.Context(), tctx, r, &result.RequestTransforms)
	// Copy any captured request body from the body_capture transform's side
	// channel onto the PipelineResult so the audit emitters can render it as
	// a top-level field. Done unconditionally so reject + error paths still
	// preserve the captured body (matches MCP's behavior at line ~333 below).
	result.BodyCapture = tctx.BodyCapture
	if err != nil {
		if markIfClientCancel(r, err, result) {
			return
		}
		result.Action = transform.ActionContinue // error, not reject
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if rejectResp != nil {
		result.Action = transform.ShortCircuitAction(result.RequestTransforms)
		result.StatusCode = rejectResp.StatusCode
		p.writeResponse(w, rejectResp)
		return
	}

	// MCP policy: evaluate the request against any matching MCP server. Runs
	// after the transform pipeline so allowlist/secrets have already applied.
	// Snapshot once per request so a hot-swap mid-request stays consistent.
	mcpPolicy := p.mcpPolicy.Load()
	var mcpServer *mcp.Server
	var mcpTrace *mcp.Trace
	if mcpPolicy != nil {
		if s := mcpPolicy.MatchServer(r); s != nil {
			mcpServer = s
			mcpTrace = &mcp.Trace{Server: s.Name}
			result.MCP = mcpTrace
			rejectResp, err := mcpPolicy.EvaluateRequest(s, r, mcpTrace)
			if err != nil {
				if markIfClientCancel(r, err, result) {
					return
				}
				result.Action = transform.ActionContinue
				result.StatusCode = http.StatusBadGateway
				result.Err = err
				http.Error(w, "bad gateway", http.StatusBadGateway)
				return
			}
			if rejectResp != nil {
				result.Action = transform.ActionReject
				result.StatusCode = rejectResp.StatusCode
				p.writeResponse(w, rejectResp)
				return
			}
		}
	}

	// WebSocket upgrade: relay raw bytes only once upstream accepts it.
	if isWebSocketUpgrade(r) {
		p.handleWebSocket(w, r, scheme, host, pl, tctx, result)
		return
	}

	upstreamScheme := scheme
	upstreamHost := host
	upstreamPath := r.URL.Path
	upstreamRawPath := r.URL.RawPath
	upstreamURL := ""

	if mcpServer != nil {
		gateway := p.mcpGateway.Load()
		if route := gateway.Match(r); route != nil {
			applied, err := route.Apply(r.Context(), r)
			if err != nil {
				if markIfClientCancel(r, err, result) {
					return
				}
				result.Action = transform.ActionContinue
				result.StatusCode = http.StatusBadGateway
				result.Err = err
				http.Error(w, "bad gateway", http.StatusBadGateway)
				return
			}
			upstreamURL = applied.RequestURL
			mcpTrace.SetGateway(map[string]any{
				"route":                applied.Name,
				"upstream":             applied.Upstream,
				"credentials_injected": applied.InjectedCredentialIDs,
			})
		}
	}

	// Build upstream request. Use r.URL (which transforms may have modified)
	// rather than r.RequestURI (which is immutable). Preserve RawPath so
	// percent-encoded reserved characters like %2F survive to the upstream —
	// some APIs (e.g. GCS object names) treat decoded vs encoded slashes as
	// distinct path segments.
	if upstreamURL == "" {
		upstreamURL = (&url.URL{
			Scheme:   upstreamScheme,
			Host:     upstreamHost,
			Path:     upstreamPath,
			RawPath:  upstreamRawPath,
			RawQuery: r.URL.RawQuery,
		}).String()
	}

	reqBody := transform.RequireBufferedBody(r.Body)
	// Check Len() before StreamingReader(), which clears the original reader.
	reqBodyLen := reqBody.Len()
	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, io.NopCloser(reqBody.StreamingReader()))
	if err != nil {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	copyHeaders(upstreamReq.Header, r.Header)
	sanitizeUpstreamHeaders(upstreamReq.Header)
	// If a transform buffered the request body, set ContentLength so the
	// upstream receives a Content-Length header instead of chunked encoding.
	// Otherwise, preserve the original Content-Length from the client.
	if reqBodyLen >= 0 {
		upstreamReq.ContentLength = int64(reqBodyLen)
	} else {
		upstreamReq.ContentLength = reqBody.ForwardedLength(r.ContentLength)
	}

	var replayBody []byte
	replayable := false
	responseRetryEnabled := p.responseRetryHandler != nil && responseRetryEligible(upstreamReq)
	if responseRetryEnabled {
		upstreamReq.Body, replayBody, replayable, err = prepareReplayBody(
			upstreamReq.Body,
			upstreamReq.ContentLength,
			bodyLimits.MaxRequestBodyBytes,
		)
		if err != nil {
			result.Action = transform.ActionContinue
			result.StatusCode = http.StatusBadGateway
			result.Err = err
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		if replayable {
			upstreamReq.ContentLength = int64(len(replayBody))
		}
	}

	resp, err := p.doUpstream(upstreamReq)
	if err != nil {
		if markIfClientCancel(r, err, result) {
			return
		}
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if responseRetryEnabled {
		chargeStarted := time.Now()
		decision, replay, retryErr := p.responseRetryHandler.Decide(r.Context(), upstreamReq, resp, replayable)
		if retryErr != nil {
			p.logger.Warn("response retry authorization failed", slog.String("error", retryErr.Error()))
		}
		if replay {
			_ = resp.Body.Close() // The 402 body is never returned after authorization.
			replayReq := upstreamReq.Clone(r.Context())
			replayReq.Body = io.NopCloser(bytes.NewReader(replayBody))
			replayReq.ContentLength = int64(len(replayBody))
			replayReq.Header = upstreamReq.Header.Clone()
			for name, values := range decision.Headers {
				replayReq.Header.Del(name)
				for _, value := range values {
					replayReq.Header.Add(name, value)
				}
			}
			if decision.Traceparent != "" {
				replayReq.Header.Set("Traceparent", decision.Traceparent)
			}
			replayStarted := time.Now()
			resp, err = p.doUpstream(replayReq)
			completionTraceparent := decision.Traceparent
			if completionTraceparent == "" {
				completionTraceparent = upstreamReq.Header.Get("Traceparent")
			}
			if err != nil {
				p.completeResponseRetry(
					r.Context(),
					decision.AttemptID,
					nil,
					"upstream_transport_error",
					completionTraceparent,
					time.Since(replayStarted),
					time.Since(chargeStarted),
				)
				if markIfClientCancel(r, err, result) {
					return
				}
				result.Action = transform.ActionContinue
				result.StatusCode = http.StatusBadGateway
				result.Err = err
				http.Error(w, "bad gateway", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			p.completeResponseRetry(
				r.Context(),
				decision.AttemptID,
				resp,
				"",
				completionTraceparent,
				time.Since(replayStarted),
				time.Since(chargeStarted),
			)
		}
	}

	// Wrap response body for lazy buffering by transforms.
	resp.Body = transform.NewBufferedBody(resp.Body, bodyLimits.MaxResponseBodyBytes)

	// Run response transforms
	finalResp, err := pl.ProcessResponse(r.Context(), tctx, r, resp, &result.ResponseTransforms)
	if err != nil {
		if markIfClientCancel(r, err, result) {
			return
		}
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	result.Action = transform.ShortCircuitAction(result.ResponseTransforms)
	result.StatusCode = finalResp.StatusCode

	// MCP response wrapping: filter tools/list payloads and other JSON-RPC
	// messages on streams from a matched MCP server. WrapResponseBody
	// returns a *transform.BufferedBody (or the original body untouched)
	// so the proxy's streamSSE/writeResponse paths can consume it directly.
	if mcpServer != nil && mcpPolicy != nil {
		ct := finalResp.Header.Get("Content-Type")
		wrapped, err := mcpPolicy.WrapResponseBody(mcpServer, ct, finalResp.Body, mcpTrace)
		if err != nil {
			p.logger.Warn("mcp response wrap error", slog.String("error", err.Error()))
		} else if wrapped != nil {
			finalResp.Body = wrapped
		}
	}

	// SSE: stream with flushing
	if isSSE(finalResp) {
		p.streamSSE(w, finalResp)
		return
	}

	p.writeResponse(w, finalResp)
}

type multiReadCloser struct {
	io.Reader
	io.Closer
}

func prepareReplayBody(body io.ReadCloser, contentLength, limit int64) (io.ReadCloser, []byte, bool, error) {
	if limit <= 0 || contentLength > limit {
		return body, nil, false, nil
	}
	replayBody, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		if closeErr := body.Close(); closeErr != nil {
			return nil, nil, false, errors.Join(err, closeErr)
		}
		return nil, nil, false, err
	}
	if int64(len(replayBody)) > limit {
		return &multiReadCloser{
			Reader: io.MultiReader(bytes.NewReader(replayBody), body),
			Closer: body,
		}, nil, false, nil
	}
	if err := body.Close(); err != nil {
		return nil, nil, false, err
	}
	return io.NopCloser(bytes.NewReader(replayBody)), replayBody, true, nil
}

func responseRetryEligible(req *http.Request) bool {
	if req.ContentLength < 0 || isWebSocketUpgrade(req) {
		return false
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.SplitN(req.Header.Get("Content-Type"), ";", 2)[0]))
	return !strings.HasPrefix(contentType, "application/grpc")
}

func (p *Proxy) completeResponseRetry(ctx context.Context, attemptID string, resp *http.Response, transportError, traceparent string, replayDuration, chargeDuration time.Duration) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := p.responseRetryHandler.Complete(ctx, attemptID, resp, transportError, traceparent, replayDuration, chargeDuration); err != nil {
		p.logger.Warn("response retry completion failed", slog.String("error", err.Error()))
	}
}

// isWebSocketUpgrade detects a WebSocket upgrade request. Connection is
// parsed as comma-separated tokens with an exact case-insensitive "upgrade"
// match so a value like "notupgrade" does not satisfy the check.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		headerHasToken(r.Header, "Connection", "upgrade")
}

// headerHasToken reports whether the named header contains an exact
// case-insensitive token (per RFC 7230 §3.2.6 comma-separated values).
func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// hopByHopHeaders are the headers consumed at the connection boundary per
// RFC 7230 §6.1, plus Proxy-Connection (a common non-standard variant).
// These must not be forwarded to the upstream.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// sanitizeUpstreamHeaders removes hop-by-hop headers and any header named
// by the client's Connection header before the request is forwarded
// upstream. Modeled after net/http/httputil.ReverseProxy.
func sanitizeUpstreamHeaders(h http.Header) {
	// Collect Connection-named tokens before deleting Connection itself.
	var connectionTokens []string
	for _, v := range h.Values("Connection") {
		for _, t := range strings.Split(v, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				connectionTokens = append(connectionTokens, t)
			}
		}
	}

	// Preserve TE: trailers for gRPC-over-HTTP/1.1 compatibility, matching
	// net/http/httputil.ReverseProxy.
	keepTrailers := headerHasToken(h, "Te", "trailers")

	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
	for _, name := range connectionTokens {
		h.Del(name)
	}
	if keepTrailers {
		h.Set("Te", "trailers")
	}
}

// handleWebSocket forwards a WebSocket upgrade request and, only if the
// upstream completes the handshake with 101 Switching Protocols, hijacks the
// client connection and relays raw bytes bidirectionally. A refused upgrade is
// returned to the client as an ordinary HTTP response so the client
// connection stays under the HTTP server and every later request on it is
// still subject to the transform pipeline.
func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request, scheme, host string, pl *transform.Pipeline, tctx *transform.TransformContext, result *transform.PipelineResult) {
	fail := func(err error) {
		if markIfClientCancel(r, err, result) {
			return
		}
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	upstreamAddr := host
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		port := "80"
		if scheme == "https" {
			port = "443"
		}
		upstreamAddr = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}

	dialer := &net.Dialer{
		Timeout:  30 * time.Second,
		Resolver: p.resolver,
		Control:  p.guard.DialControl,
	}
	var upstreamConn net.Conn
	var err error
	if scheme == "https" {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: &tls.Config{MinVersion: tls.VersionTLS12}}
		upstreamConn, err = tlsDialer.DialContext(r.Context(), "tcp", upstreamAddr)
	} else {
		upstreamConn, err = dialer.DialContext(r.Context(), "tcp", upstreamAddr)
	}
	if err != nil {
		p.logger.Error("websocket upstream dial failed",
			slog.String("host", host),
			slog.String("error", err.Error()),
		)
		fail(err)
		return
	}
	defer upstreamConn.Close()
	// The request context ends when the client goes away or the handler
	// returns; close the upstream then so a blocked read is released.
	stop := context.AfterFunc(r.Context(), func() { _ = upstreamConn.Close() })
	defer stop()

	// Build the outbound request from the validated destination rather than
	// re-serializing the inbound request line, so the authority the upstream
	// routes on is exactly the one policy evaluated. Sanitize headers so
	// client-supplied Proxy-Authorization, hop-by-hop headers, and
	// Connection-named tokens are not leaked, then re-set the upgrade headers.
	outReq := r.Clone(r.Context())
	outReq.URL = &url.URL{Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	outReq.Host = host
	outReq.RequestURI = ""
	sanitizeUpstreamHeaders(outReq.Header)
	outReq.Header.Set("Connection", "Upgrade")
	outReq.Header.Set("Upgrade", "websocket")

	if err := outReq.Write(upstreamConn); err != nil {
		p.logger.Error("websocket upstream write failed", slog.String("error", err.Error()))
		fail(err)
		return
	}

	if timeout := p.transport.ResponseHeaderTimeout; timeout > 0 {
		if err := upstreamConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			fail(err)
			return
		}
	}
	upstreamBuf := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamBuf, outReq)
	if err != nil {
		p.logger.Error("websocket upstream response read failed", slog.String("error", err.Error()))
		fail(err)
		return
	}
	defer resp.Body.Close()
	if err := upstreamConn.SetReadDeadline(time.Time{}); err != nil {
		fail(err)
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		!headerHasToken(resp.Header, "Connection", "upgrade") {
		p.writeRefusedUpgrade(w, r, pl, tctx, result, resp)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		p.logger.Error("websocket hijack not supported")
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusInternalServerError
		result.Err = errors.New("websocket hijack not supported")
		http.Error(w, "websocket not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		p.logger.Error("websocket hijack failed", slog.String("error", err.Error()))
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		return
	}

	result.Action = transform.ActionContinue
	result.StatusCode = http.StatusSwitchingProtocols

	// Forward the upstream's handshake response verbatim (status line and
	// headers; a 101 carries no body).
	if _, err := clientBuf.WriteString("HTTP/1.1 " + resp.Status + "\r\n"); err != nil {
		p.logger.Warn("websocket handshake write failed", slog.String("error", err.Error()))
		clientConn.Close()
		return
	}
	if err := resp.Header.Write(clientBuf); err != nil {
		p.logger.Warn("websocket handshake write failed", slog.String("error", err.Error()))
		clientConn.Close()
		return
	}
	if _, err := clientBuf.WriteString("\r\n"); err != nil {
		p.logger.Warn("websocket handshake write failed", slog.String("error", err.Error()))
		clientConn.Close()
		return
	}
	if err := clientBuf.Flush(); err != nil {
		p.logger.Warn("websocket handshake write failed", slog.String("error", err.Error()))
		clientConn.Close()
		return
	}

	// Relay until either side closes or the proxy shuts down. Both buffered
	// readers may hold bytes already read off the wire, so drain them first.
	proxyBidi(p.shutdownCtx, newPeekedConn(clientConn, clientBuf.Reader), newPeekedConn(upstreamConn, upstreamBuf), p.logger, "websocket")

	p.logger.Debug("websocket connection closed", slog.String("host", host))
}

// writeRefusedUpgrade returns an upstream's non-101 reply to a WebSocket
// upgrade as an ordinary HTTP response, running response transforms as for
// any other request. The upstream connection is not reused.
func (p *Proxy) writeRefusedUpgrade(w http.ResponseWriter, r *http.Request, pl *transform.Pipeline, tctx *transform.TransformContext, result *transform.PipelineResult, resp *http.Response) {
	sanitizeUpstreamHeaders(resp.Header)
	resp.Body = transform.NewBufferedBody(resp.Body, pl.BodyLimits().MaxResponseBodyBytes)

	finalResp, err := pl.ProcessResponse(r.Context(), tctx, r, resp, &result.ResponseTransforms)
	if err != nil {
		if markIfClientCancel(r, err, result) {
			return
		}
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	result.Action = transform.ShortCircuitAction(result.ResponseTransforms)
	result.StatusCode = finalResp.StatusCode
	p.writeResponse(w, finalResp)
}

// isSSE detects a Server-Sent Events response.
func isSSE(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "text/event-stream")
}

// streamSSE writes an SSE response with per-chunk flushing.
func (p *Proxy) streamSSE(w http.ResponseWriter, resp *http.Response) {
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	reader := transform.RequireBufferedBody(resp.Body).StreamingReader()

	flusher, ok := w.(http.Flusher)
	if !ok {
		if _, err := io.Copy(w, reader); err != nil {
			p.logger.Warn("SSE copy error", slog.String("error", err.Error()))
		}
		return
	}

	buf := make([]byte, 32*1024)
	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				p.logger.Warn("SSE write error", slog.String("error", writeErr.Error()))
				break
			}
			flusher.Flush()
		}
		if readErr != nil {
			if readErr != io.EOF {
				p.logger.Warn("SSE read error", slog.String("error", readErr.Error()))
			}
			break
		}
	}
}

func (p *Proxy) writeResponse(w http.ResponseWriter, resp *http.Response) {
	copyHeaders(w.Header(), resp.Header)
	// Forward upstream trailers (e.g. gRPC status) after the body. HTTP/1.1
	// sends trailers only on a chunked body, so a response that has them drops
	// any fixed length and declares their names before the header is written.
	if len(resp.Trailer) > 0 {
		w.Header().Del("Content-Length")
	}
	for name := range resp.Trailer {
		w.Header().Add("Trailer", name)
	}
	defer writeTrailers(w, resp)
	if buf, ok := resp.Body.(*transform.BufferedBody); ok {
		// If a transform buffered the response body, set Content-Length
		// from the buffered data. Otherwise preserve the upstream header
		// as-is so clients that require Content-Length (e.g. Docker)
		// work correctly. A response with trailers stays chunked.
		if n := buf.Len(); n >= 0 && len(resp.Trailer) == 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(int64(n), 10))
		}
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, buf.StreamingReader()); err != nil {
			p.logger.Warn("response body copy error", slog.String("error", err.Error()))
		}
	} else {
		// Synthetic responses (e.g. reject) with plain bodies.
		w.WriteHeader(resp.StatusCode)
		if resp.Body != nil {
			if _, err := io.Copy(w, resp.Body); err != nil {
				p.logger.Warn("response body copy error", slog.String("error", err.Error()))
			}
		}
	}
}

// buildTransport creates the HTTP transport used for upstream requests.
// If resolver is non-nil, the transport's dialer uses it instead of the OS
// default — this prevents resolution loops when iron-proxy owns the system DNS.
// guard's DialControl is wired in so a hostname that resolves to a denied IP
// is rejected before the TCP connect.
// responseHeaderTimeout overrides the default 30-second
// ResponseHeaderTimeout when greater than zero; pass 0 to keep the default.
// proxyFunc, when non-nil, routes upstream requests through an upstream
// SOCKS5/HTTP CONNECT proxy; the dialer (and thus guard.DialControl) then
// applies to the proxy connection rather than the final target.
func buildTransport(resolver *net.Resolver, guard *dnsguard.Guard, responseHeaderTimeout time.Duration, proxyFunc func(*http.Request) (*url.URL, error)) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  resolver,
		Control:   guard.DialControl,
	}
	if responseHeaderTimeout <= 0 {
		responseHeaderTimeout = config.DefaultUpstreamResponseHeaderTimeout
	}
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		Proxy:       proxyFunc,
		DialContext: dialer.DialContext,
		// A custom DialContext disables net/http's automatic HTTP/2; opt back in
		// so gRPC upstreams negotiate h2 over the same (dnsguard-controlled) dialer.
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
}

func (p *Proxy) doUpstream(req *http.Request) (*http.Response, error) {
	return p.transport.RoundTrip(req)
}

// markIfClientCancel records a client-initiated cancellation on result and
// returns true; callers should then return without writing a 502. The wrapped
// errors.Is on err catches transforms that report context.Canceled without
// observing r.Context() directly.
func markIfClientCancel(r *http.Request, err error, result *transform.PipelineResult) bool {
	if !errors.Is(r.Context().Err(), context.Canceled) && !errors.Is(err, context.Canceled) {
		return false
	}
	result.Action = transform.ActionContinue
	result.StatusCode = http.StatusOK
	result.ClientCanceled = true
	return true
}

// containsDotSegments reports whether p has any "." or ".." path segment.
// Backslash is treated as a separator (IIS, ASP.NET) and ";" path parameters
// are ignored (Tomcat, Jetty, Spring), so "..\\" and "..;" are caught too.
func containsDotSegments(p string) bool {
	isSep := func(r rune) bool { return r == '/' || r == '\\' }
	for _, seg := range strings.FieldsFunc(p, isSep) {
		seg, _, _ = strings.Cut(seg, ";")
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// writeTrailers forwards upstream response trailers (e.g. gRPC status) to the
// client after the body, via the TrailerPrefix convention.
func writeTrailers(w http.ResponseWriter, resp *http.Response) {
	for k, vs := range resp.Trailer {
		for _, v := range vs {
			w.Header().Add(http.TrailerPrefix+k, v)
		}
	}
}
