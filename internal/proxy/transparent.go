package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenTransparent starts the TPROXY ingress.
//
// The listener is bound with IP_TRANSPARENT so nftables/policy-routing can hand
// it connections addressed to *any* destination, and each accepted socket
// carries the connection's ORIGINAL destination as its local address. That is
// the whole point of TPROXY over DNAT: DNAT rewrites the destination away, so a
// proxy behind it can never learn the real host:port; TPROXY preserves it. This
// lets one kernel rule intercept every TCP port instead of one DNAT per port.
//
// There is no client handshake here — unlike the tunnel listener, the client is
// not speaking proxy protocol, it believes it is talking to the destination.
// So the destination comes off the socket, and the connection is dispatched
// through the same transform pipeline (default-deny allowlist) and the same
// MITM/plain-HTTP handling as a tunnelled connection.
func (p *Proxy) listenTransparent() error {
	lc := net.ListenConfig{Control: transparentControl}
	ln, err := lc.Listen(context.Background(), "tcp", p.transparentAddr)
	if err != nil {
		return fmt.Errorf("transparent listen: %w", err)
	}
	p.transparentListener = ln
	p.logger.Info("transparent (tproxy) proxy starting", slog.String("addr", ln.Addr().String()))

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-p.transparentDone:
				return nil
			default:
			}
			p.logger.Warn("transparent accept error", slog.String("error", err.Error()))
			continue
		}
		go p.handleTransparent(conn)
	}
}

// transparentControl sets IP_TRANSPARENT on the listening socket.
//
// This is setup-only privilege: it is the socket option that makes the kernel
// willing to deliver non-local destinations to this listener. Accepted sockets
// inherit it, and serving them (read/write) needs no capability at all, so the
// process can drop NET_ADMIN after the listener is bound. Failure is fatal for
// this listener only — it means the TPROXY rules would silently never match, so
// we refuse to pretend the ingress is up.
func transparentControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	}); err != nil {
		return err
	}
	return serr
}

// handleTransparent serves one transparently-intercepted connection.
func (p *Proxy) handleTransparent(conn net.Conn) {
	defer conn.Close()

	target, err := transparentTarget(conn)
	if err != nil {
		p.logger.Warn("transparent connection has no original destination",
			slog.String("remote", conn.RemoteAddr().String()),
			slog.String("error", err.Error()),
		)
		return
	}

	p.logger.Debug("transparent connection", slog.String("target", target))

	// Same policy gate as the tunnel listener: a synthetic CONNECT evaluated
	// against the allowlist and secrets transforms, so transparent traffic is
	// subject to the same default-deny posture (and emits the same audit
	// entry) as anything else.
	ok, rejectResp, tunnelInfo := p.tunnelTransformCheck(conn.RemoteAddr().String(), target, nil)
	if !ok {
		status := 0
		if rejectResp != nil {
			status = rejectResp.StatusCode
		}
		p.logger.Info("transparent connection denied by transform",
			slog.String("target", target),
			slog.Int("status", status),
		)
		return
	}

	if err := p.serveTunnel(conn, target, tunnelInfo); err != nil {
		p.logger.Debug("transparent serve error",
			slog.String("target", target),
			slog.String("error", err.Error()),
		)
	}
}

// transparentTarget recovers the destination the client originally addressed.
//
// With TPROXY the kernel assigns the original destination as the accepted
// socket's local address, so it is read back from the socket rather than from a
// client-supplied CONNECT line or SOCKS5 request. An unspecified address means
// the socket never received a transparent destination — the usual cause is a
// missing/incorrect TPROXY rule or policy route, so it is reported loudly
// instead of being served as a bogus 0.0.0.0 target.
func transparentTarget(conn net.Conn) (string, error) {
	local := conn.LocalAddr()
	addr, ok := local.(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("unexpected local address type %T", local)
	}
	if addr.IP == nil || addr.IP.IsUnspecified() {
		return "", fmt.Errorf("original destination not preserved on socket (local address %s): check the TPROXY rule and policy route", addr.String())
	}
	return addr.String(), nil
}
