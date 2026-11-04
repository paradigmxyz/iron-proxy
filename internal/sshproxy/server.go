package sshproxy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/transform"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// Server accepts only its paired sandbox's disposable public key.
type Server struct {
	HostKey          ssh.Signer
	ClientPublicKey  ssh.PublicKey
	Authorize        Authorizer
	Guard            *dnsguard.Guard
	Audit            transform.AuditFunc
	TLSRootCAs       *x509.CertPool
	Logger           *slog.Logger
	RenewalInterval  time.Duration
	HandshakeTimeout time.Duration
}

// session is one authorized upstream connection.
type session struct {
	auth  Authorization
	grant *Grant
	conn  ssh.Conn
	chans <-chan ssh.NewChannel
	reqs  <-chan *ssh.Request
}

func (s *Server) Serve(parent context.Context, listener net.Listener) error {
	if s.HostKey == nil || s.ClientPublicKey == nil || s.Authorize == nil || s.Guard == nil || s.Audit == nil || s.Logger == nil {
		return errors.New("incomplete SSH configuration")
	}
	ctx, cancel := context.WithCancel(parent)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() { defer wg.Done(); s.handle(ctx, conn) }()
	}
}

func (s *Server) handle(parent context.Context, conn net.Conn) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	started := time.Now()
	remote := conn.RemoteAddr().String()
	timeout := s.HandshakeTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, timeout)
	defer handshakeCancel()
	handshakeDeadline, _ := handshakeCtx.Deadline()
	if conn.SetDeadline(handshakeDeadline) != nil {
		return
	}
	var sess *session
	defer func() {
		if sess != nil {
			_ = sess.conn.Close()
		}
	}()
	attempted := false
	config := &ssh.ServerConfig{
		// Also runs for unsigned key queries, so it must only compare keys.
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(key.Marshal(), s.ClientPublicKey.Marshal()) {
				return nil, errAccessDenied
			}
			return nil, nil
		},
		// Runs only after the client proves possession of the paired key.
		VerifiedPublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey, _ *ssh.Permissions, _ string) (*ssh.Permissions, error) {
			attempted = true
			attemptStarted := time.Now()
			next, err := s.connect(handshakeCtx, meta.User(), key, handshakeDeadline)
			s.audit(attemptStarted, remote, next, "auth", next.auth.Route, "ssh_authorization", err)
			if err != nil {
				return nil, err
			}
			sess = next
			return nil, nil
		},
	}
	config.AddHostKey(s.HostKey)
	downstream, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		if !attempted {
			s.audit(started, remote, nil, "auth", "", "ssh_authorization", fmt.Errorf("%w: %v", errAccessDenied, err))
		}
		return
	}
	defer downstream.Close()
	if conn.SetDeadline(time.Time{}) != nil {
		return
	}
	handshakeCancel()
	stopUpstream := context.AfterFunc(ctx, func() { _ = sess.conn.Close() })
	defer stopUpstream()

	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	// Wait's error only says why upstream closed; either way the session ends.
	run(func() { _ = sess.conn.Wait(); cancel() })
	run(func() { s.renew(ctx, cancel, sess.auth, sess.grant) })
	// Global requests (forwarding, keepalives) are refused in both directions.
	run(func() { ssh.DiscardRequests(reqs) })
	run(func() { ssh.DiscardRequests(sess.reqs) })
	run(func() {
		for nc := range sess.chans {
			_ = nc.Reject(ssh.Prohibited, "upstream channels are not permitted") // peer is being refused; a failed send changes nothing
		}
	})
	for nc := range chans {
		if nc.ChannelType() != "session" {
			s.audit(time.Now(), remote, sess, nc.ChannelType(), "", "ssh_policy", errCapabilityDenied)
			_ = nc.Reject(ssh.Prohibited, "only session channels are permitted") // as above
			continue
		}
		run(func() { s.bridge(nc, sess, remote) })
	}
	cancel()
	_ = sess.conn.Close()
	wg.Wait()
}

// bridge pairs one downstream session channel with a new upstream one.
func (s *Server) bridge(nc ssh.NewChannel, sess *session, remote string) {
	up, upReqs, err := sess.conn.OpenChannel("session", nc.ExtraData())
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "upstream session unavailable") // refusal is best effort
		return
	}
	down, downReqs, err := nc.Accept()
	if err != nil {
		_ = up.Close()
		return
	}
	// Upstream output, including exit-status requests, must be delivered
	// before the downstream channel closes.
	var output sync.WaitGroup
	output.Add(3)
	go func() { defer output.Done(); _, _ = io.Copy(down, up) }()
	go func() { defer output.Done(); _, _ = io.Copy(down.Stderr(), up.Stderr()) }()
	go func() {
		defer output.Done()
		for req := range upReqs {
			ok, _ := down.SendRequest(req.Type, req.WantReply, req.Payload) // a send failure means the client is gone; report false
			_ = req.Reply(ok, nil)                                          // upstream channel may already be closed
		}
	}()
	closed := make(chan struct{})
	go func() { defer close(closed); output.Wait(); _ = down.Close() }()
	input := make(chan struct{})
	go func() { defer close(input); _, _ = io.Copy(up, down); _ = up.CloseWrite() }()

	for req := range downReqs {
		started := time.Now()
		decision, detail := sessionRequestPolicy(req.Type, req.Payload)
		if decision != forwardRequest {
			if decision == refuseRequest {
				s.audit(started, remote, sess, req.Type, detail, "ssh_policy", errCapabilityDenied)
			}
			_ = req.Reply(false, nil) // client may already be gone
			continue
		}
		ok, err := up.SendRequest(req.Type, req.WantReply, req.Payload)
		s.audit(started, remote, sess, req.Type, detail, "ssh_policy", err)
		_ = req.Reply(ok, nil) // client may already be gone
	}
	_ = up.Close()
	<-closed
	<-input
}

// connect authorizes the route and logs in upstream with the granted key.
// The returned session is never nil so failures can still be audited.
func (s *Server) connect(ctx context.Context, user string, key ssh.PublicKey, deadline time.Time) (*session, error) {
	sess := &session{}
	route, destination, err := parseRoute(user)
	if err != nil {
		return sess, fmt.Errorf("%w: %v", errAccessDenied, err)
	}
	sess.auth = Authorization{Route: route, Destination: destination, PublicKey: string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(key)))}
	grant, err := s.Authorize(ctx, sess.auth)
	if err != nil {
		return sess, err
	}
	if err = validateGrant(grant); err != nil {
		return sess, err
	}
	sess.grant = grant
	credential, err := signer(ctx, grant.PrivateKey, s.Logger)
	if err != nil {
		return sess, err
	}
	var expected ssh.PublicKey
	var algorithms []string
	if !grant.TLSIdentity {
		expected, _, _, _, err = ssh.ParseAuthorizedKey([]byte(grant.HostKey))
		if err != nil {
			return sess, errors.New("invalid upstream host identity")
		}
		algorithms = []string{expected.Type()}
		if expected.Type() == ssh.KeyAlgoRSA {
			algorithms = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
		}
	}
	netConn, err := transport(ctx, grant.Destination, s.Guard, s.TLSRootCAs)
	if err != nil {
		return sess, fmt.Errorf("SSH upstream unavailable: %w", err)
	}
	if err = netConn.SetDeadline(deadline); err != nil {
		_ = netConn.Close()
		return sess, err
	}
	config := &ssh.ClientConfig{
		User:              grant.Username,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(credential)},
		HostKeyAlgorithms: algorithms,
		HostKeyCallback: func(_ string, _ net.Addr, actual ssh.PublicKey) error {
			// TLS-identity grants are WSS-only (validated before dialing). The
			// transport authenticates the exact URL's server certificate with no
			// redirects or insecure TLS option; SSH remains inside that tunnel.
			if expected != nil && !bytes.Equal(expected.Marshal(), actual.Marshal()) {
				return errors.New("SSH host identity mismatch")
			}
			return nil
		},
	}
	conn, chans, reqs, err := ssh.NewClientConn(netConn, grant.Destination, config)
	if err != nil {
		_ = netConn.Close()
		return sess, fmt.Errorf("SSH upstream login failed: %w", err)
	}
	if err = netConn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return sess, err
	}
	sess.conn, sess.chans, sess.reqs = conn, chans, reqs
	return sess, nil
}

// audit emits one SSH event through the proxy's shared audit sinks.
func (s *Server) audit(started time.Time, remote string, sess *session, method, path, name string, err error) {
	trace := transform.TransformTrace{Name: name, Duration: time.Since(started), Annotations: map[string]any{}}
	result := &transform.PipelineResult{
		Method:     method,
		Path:       path,
		RemoteAddr: remote,
		Mode:       transform.ModeSSH,
		StartedAt:  started,
		Duration:   time.Since(started),
	}
	if sess != nil {
		if sess.auth.Route != "" {
			trace.Annotations["route"] = sess.auth.Route
		}
		if g := sess.grant; g != nil {
			trace.Annotations["principal"] = g.Principal
			trace.Annotations["grant_id"] = g.ID
			if u, err := url.Parse(g.Destination); err == nil {
				result.Host = u.Host
			}
		}
	}
	switch {
	case errors.Is(err, errAccessDenied) || errors.Is(err, errCapabilityDenied):
		result.Action, trace.Action = transform.ActionReject, transform.ActionReject
		trace.Annotations["reason"] = err.Error()
	case err != nil:
		result.Err, trace.Err = err, err
	}
	result.RequestTransforms = []transform.TransformTrace{trace}
	s.Audit(result)
}

func validateGrant(g *Grant) error {
	if g == nil || g.ID == "" || g.Principal == "" || g.Generation == "" || g.Username == "" || g.Destination == "" || !g.ExpiresAt.After(time.Now()) || time.Until(g.ExpiresAt) > 15*time.Minute {
		return errors.New("invalid SSH grant")
	}
	if g.TLSIdentity {
		u, err := url.Parse(g.Destination)
		if err != nil || u.Scheme != "wss" || g.HostKey != "" {
			return errors.New("invalid TLS identity grant")
		}
	} else if g.HostKey == "" {
		return errors.New("SSH host key required")
	}
	return nil
}

// A client may name a destination, but only the authorizer can approve it.
// The encoded value carries no credentials and is bounded before decoding.
func parseRoute(value string) (string, string, error) {
	if strings.HasPrefix(value, "ee:") {
		if len(value) > 4096 {
			return "", "", errors.New("invalid SSH target")
		}
		data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "ee:"))
		if err != nil || len(data) == 0 || len(data) > 2048 {
			return "", "", errors.New("invalid SSH target")
		}
		return "ee", string(data), nil
	}
	if len(value) == 0 || len(value) > 128 {
		return "", "", errors.New("invalid SSH route")
	}
	return value, "", nil
}

func (s *Server) renew(ctx context.Context, cancel context.CancelFunc, a Authorization, g *Grant) {
	interval := s.RenewalInterval
	if interval == 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	expiry := time.AfterFunc(time.Until(g.ExpiresAt), cancel)
	defer expiry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			next, err := s.Authorize(ctx, a)
			if err != nil || validateGrant(next) != nil || !sameGrant(g, next) {
				if ctx.Err() == nil {
					s.Logger.Warn("SSH lease revoked", slog.String("grant_id", g.ID), slog.String("principal", g.Principal))
				}
				cancel()
				return
			}
			expiry.Reset(time.Until(next.ExpiresAt))
		}
	}
}
func sameGrant(a, b *Grant) bool {
	if a == nil || b == nil {
		return false
	}
	x, y := *a, *b
	x.ExpiresAt = time.Time{}
	y.ExpiresAt = time.Time{}
	x.PrivateKey, y.PrivateKey = yaml.Node{}, yaml.Node{}
	if !reflect.DeepEqual(x, y) {
		return false
	}
	var sourceA, sourceB any
	if a.PrivateKey.Decode(&sourceA) != nil || b.PrivateKey.Decode(&sourceB) != nil {
		return false
	}
	return reflect.DeepEqual(sourceA, sourceB)
}

// ParseHostKey resolves a proxy-only credential source.
func ParseHostKey(ctx context.Context, source yaml.Node, logger *slog.Logger) (ssh.Signer, error) {
	return signer(ctx, source, logger)
}
