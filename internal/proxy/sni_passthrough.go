package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ironsh/iron-proxy/internal/transform"
)

const (
	sniPeekTimeout     = 5 * time.Second
	sniUpstreamDial    = 30 * time.Second
	defaultSNIUpstream = "443"
)

// handleSNIPassthrough is the connection handler used by the HTTPS listener
// when tls.mode is "sni-only". It peeks the SNI from the ClientHello, runs
// the transform pipeline with a host-only synthetic request, and on accept
// TCP-passthroughs the connection to the upstream server.
func (p *Proxy) handleSNIPassthrough(clientConn net.Conn) {
	if err := p.serveSNIPassthrough(clientConn); err != nil {
		p.logger.Debug("sni passthrough error", slog.String("error", err.Error()))
	}
}

// serveSNIPassthrough peeks SNI, runs the pipeline, and TCP-passthroughs the
// connection to the SNI host on port 443 if allowed. Used by both the HTTPS
// listener and the CONNECT/SOCKS5 tunnel TLS branch in sni-only mode. The
// upstream port is fixed at 443 — a client-supplied CONNECT port is ignored
// so an attacker cannot pivot an allowlisted hostname onto a different port.
func (p *Proxy) serveSNIPassthrough(clientConn net.Conn) error {
	defer clientConn.Close()

	sni, peeked, err := peekSNI(clientConn, sniPeekTimeout)
	if err != nil {
		return fmt.Errorf("peek sni: %w", err)
	}

	// Set up audit first so even empty-SNI rejections get logged.
	result := &transform.PipelineResult{
		Host:       sni,
		RemoteAddr: clientConn.RemoteAddr().String(),
		SNI:        sni,
		Mode:       transform.ModeSNIOnly,
	}
	pl, finish := p.beginPipelineRun(result)
	defer finish()

	if !p.isReady() {
		markNotReady(result)
		return nil
	}

	if sni == "" {
		result.Action = transform.ActionReject
		result.StatusCode = http.StatusBadRequest
		result.Err = fmt.Errorf("client hello missing sni")
		return result.Err
	}

	tctx := &transform.TransformContext{
		Logger: p.logger,
		SNI:    sni,
		Mode:   transform.ModeSNIOnly,
	}

	req := &http.Request{
		Host:       sni,
		URL:        &url.URL{Scheme: "https", Host: sni},
		Header:     http.Header{},
		RemoteAddr: clientConn.RemoteAddr().String(),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	req.Body = transform.NewBufferedBody(http.NoBody, 0)

	ctx, cancel := context.WithCancel(p.shutdownCtx)
	defer cancel()

	rejectResp, pipelineErr := pl.ProcessRequest(ctx, tctx, req, &result.RequestTransforms)
	if pipelineErr != nil {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = pipelineErr
		return fmt.Errorf("pipeline error for %q: %w", sni, pipelineErr)
	}
	if rejectResp != nil {
		result.Action = transform.ShortCircuitAction(result.RequestTransforms)
		result.StatusCode = rejectResp.StatusCode
		p.logger.Info("sni passthrough short-circuited by transform",
			slog.String("sni", sni),
			slog.Int("status", rejectResp.StatusCode),
		)
		return nil
	}

	// Dial upstream using the proxy's resolver so SNI → IP lookup goes via
	// the configured upstream DNS (not the proxy's own intercepting server).
	// The guard's DialControl rejects denied IPs after resolution.
	dialer := &net.Dialer{
		Timeout:  sniUpstreamDial,
		Resolver: p.resolver,
		Control:  p.guard.DialControl,
	}
	port := p.sniUpstreamPort
	if port == "" {
		port = defaultSNIUpstream
	}
	upstream, err := p.guard.DialContext(ctx, dialer, "tcp", net.JoinHostPort(sni, port))
	if err != nil {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		return fmt.Errorf("dial upstream %s: %w", sni, err)
	}
	defer upstream.Close()

	// Replay the peeked ClientHello bytes to upstream.
	if _, err := upstream.Write(peeked); err != nil {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		return fmt.Errorf("replay client hello to %s: %w", sni, err)
	}

	result.Action = transform.ActionContinue
	result.StatusCode = http.StatusOK

	// Proxy bidirectionally until either side closes or the proxy shuts down.
	proxyBidi(p.shutdownCtx, clientConn, upstream, p.logger)
	return nil
}

// proxyBidi copies bytes between two connections in both directions. When
// either direction ends (EOF, error, or ctx cancellation), both connections
// are closed so the other direction unblocks.
func proxyBidi(ctx context.Context, a, b net.Conn, logger *slog.Logger) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		_ = a.Close()
		_ = b.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(b, a); err != nil {
			logger.Debug("sni passthrough a->b copy error", slog.String("error", err.Error()))
		}
		cancel()
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(a, b); err != nil {
			logger.Debug("sni passthrough b->a copy error", slog.String("error", err.Error()))
		}
		cancel()
	}()

	wg.Wait()
}
