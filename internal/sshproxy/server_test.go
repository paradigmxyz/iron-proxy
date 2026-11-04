package sshproxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func key(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(private, "")
	require.NoError(t, err)
	return signer, pem.EncodeToMemory(block)
}

// testBackend is a real SSH server that accepts only userKey as user "dev".
// exec replies "ok:<command>" with exit status 7; "hold" blocks on stdin and
// "stream-output" writes 12 MiB. The sftp subsystem serves a temp directory.
func testBackend(t *testing.T, host, userKey ssh.Signer) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })
	root := t.TempDir()
	alternatePrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	alternateHost, err := ssh.NewSignerFromKey(alternatePrivate)
	require.NoError(t, err)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				cfg := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					if meta.User() != "dev" || !bytes.Equal(key.Marshal(), userKey.PublicKey().Marshal()) {
						return nil, errors.New("wrong upstream identity")
					}
					return nil, nil
				}}
				// A second host key ensures the proxy negotiates the pinned one.
				cfg.AddHostKey(alternateHost)
				cfg.AddHostKey(host)
				server, channels, requests, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return // some tests provoke handshake failures on purpose
				}
				defer func() { _ = server.Close() }()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					if channel.ChannelType() != "session" {
						_ = channel.Reject(ssh.UnknownChannelType, "session required")
						continue
					}
					stream, reqs, err := channel.Accept()
					if err != nil {
						return
					}
					go serveBackendSession(stream, reqs, root)
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// Errors are ignored below: this is the test peer, and failures surface as
// assertion failures in the client.
func serveBackendSession(stream ssh.Channel, reqs <-chan *ssh.Request, root string) {
	defer func() { _ = stream.Close() }()
	for req := range reqs {
		switch req.Type {
		case "exec":
			var cmd struct{ Command string }
			if ssh.Unmarshal(req.Payload, &cmd) != nil || req.Reply(true, nil) != nil {
				return
			}
			if cmd.Command == "hold" {
				_, _ = io.Copy(io.Discard, stream)
				return
			}
			output := []byte("ok:" + cmd.Command)
			if cmd.Command == "stream-output" {
				output = bytes.Repeat([]byte("output"), 1<<21)
			}
			if _, err := stream.Write(output); err != nil {
				return
			}
			_, _ = stream.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{7}))
			return
		case "subsystem":
			var sub struct{ Name string }
			if ssh.Unmarshal(req.Payload, &sub) != nil || sub.Name != "sftp" {
				_ = req.Reply(false, nil)
				return
			}
			if req.Reply(true, nil) != nil {
				return
			}
			server, err := sftp.NewServer(stream, sftp.WithServerWorkingDirectory(root))
			if err != nil {
				return
			}
			_ = server.Serve()
			_ = server.Close()
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func grant(t *testing.T, address string, host ssh.Signer, private []byte) *Grant {
	t.Helper()
	var source yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte("type: control_plane\nvalue: "+string(mustJSON(t, string(private)))), &source))
	return &Grant{ID: "grant-one", Principal: "user-a", Generation: "one", Destination: "tcp://" + address, Username: "dev", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host.PublicKey()))), PrivateKey: source, ExpiresAt: time.Now().Add(time.Minute)}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return data
}

type auditLog struct {
	mu     sync.Mutex
	events []*transform.PipelineResult
}

func (l *auditLog) record(r *transform.PipelineResult) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, r)
}

func (l *auditLog) all() []*transform.PipelineResult {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*transform.PipelineResult(nil), l.events...)
}

// recordAuth returns g for every request and records what was asked.
type recordAuth struct {
	mu    sync.Mutex
	g     *Grant
	calls []Authorization
}

func (r *recordAuth) authorize(_ context.Context, a Authorization) (*Grant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, a)
	return r.g, nil
}

func (r *recordAuth) requests() []Authorization {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Authorization(nil), r.calls...)
}

// serveProxy runs server on a loopback listener. Unset Guard, Audit, and
// Logger default to an empty guard (the backends are on loopback), a
// recording audit sink, and a discarding logger.
func serveProxy(t *testing.T, server *Server) (string, *auditLog) {
	t.Helper()
	audits := &auditLog{}
	if server.Guard == nil {
		server.Guard = &dnsguard.Guard{}
	}
	if server.Audit == nil {
		server.Audit = audits.record
	}
	if server.Logger == nil {
		server.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if server.RenewalInterval == 0 {
		server.RenewalInterval = 20 * time.Millisecond
	}
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() { cancel(); require.NoError(t, <-done) })
	return listener.Addr().String(), audits
}

func testProxy(t *testing.T, clientKey, hostKey ssh.Signer, auth Authorizer, roots *x509.CertPool) (string, *auditLog) {
	t.Helper()
	return serveProxy(t, &Server{HostKey: hostKey, ClientPublicKey: clientKey.PublicKey(), Authorize: auth, TLSRootCAs: roots})
}

func connect(address string, key, host ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", address, &ssh.ClientConfig{User: "ee", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: time.Second})
}

// backendFixture is a backend plus a grant that reaches it.
func backendFixture(t *testing.T) *Grant {
	t.Helper()
	backendHost, _ := key(t)
	upstreamKey, private := key(t)
	return grant(t, testBackend(t, backendHost, upstreamKey), backendHost, private)
}

func TestExecSFTPAndKeyIsolation(t *testing.T) {
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	backendHost, _ := key(t)
	realKey, private := key(t)
	target := testBackend(t, backendHost, realKey)
	auth := &recordAuth{g: grant(t, target, backendHost, private)}
	address, _ := testProxy(t, clientKey, proxyHost, auth.authorize, nil)
	client, err := connect(address, clientKey, proxyHost)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	session, err := client.NewSession()
	require.NoError(t, err)
	output, err := session.Output("test-command")
	var exit *ssh.ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, 7, exit.ExitStatus())
	require.Equal(t, "ok:test-command", string(output))
	files, err := sftp.NewClient(client)
	require.NoError(t, err)
	defer func() { _ = files.Close() }()
	remote, err := files.Create("fixture.txt")
	require.NoError(t, err)
	_, err = remote.Write([]byte("edited"))
	require.NoError(t, err)
	require.NoError(t, remote.Close())
	remote, err = files.Open("fixture.txt")
	require.NoError(t, err)
	data, err := io.ReadAll(remote)
	require.NoError(t, err)
	require.Equal(t, "edited", string(data))
	require.NoError(t, remote.Close())
	require.Len(t, auth.requests(), 1)
	require.Equal(t, "ee", auth.requests()[0].Route)

	wrong, _ := key(t)
	_, err = connect(address, wrong, proxyHost)
	require.Error(t, err)
	_, err = connect(address, clientKey, backendHost)
	require.Error(t, err, "client must pin the proxy's host key, not the backend's")
}

func TestRefusalsAreAuditedAndKeepConnection(t *testing.T) {
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	g := backendFixture(t)
	target := strings.TrimPrefix(g.Destination, "tcp://")
	auth := &recordAuth{g: g}
	address, audits := testProxy(t, clientKey, proxyHost, auth.authorize, nil)
	client, err := connect(address, clientKey, proxyHost)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	refused, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, refused.RequestPty("xterm", 24, 80, nil))
	require.NoError(t, refused.Close())
	_, err = client.Dial("tcp", "example.com:80")
	require.Error(t, err)

	session, err := client.NewSession()
	require.NoError(t, err)
	out, err := session.Output("git-upload-pack 'repo'")
	var exit *ssh.ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, "ok:git-upload-pack 'repo'", string(out))

	events := audits.all()
	methods := make([]string, len(events))
	for i, e := range events {
		methods[i] = e.Method
		require.Equal(t, transform.ModeSSH, e.Mode)
		require.Equal(t, target, e.Host)
		require.Len(t, e.RequestTransforms, 1)
		require.Equal(t, "user-a", e.RequestTransforms[0].Annotations["principal"])
		require.Equal(t, "grant-one", e.RequestTransforms[0].Annotations["grant_id"])
	}
	require.Equal(t, []string{"auth", "pty-req", "direct-tcpip", "exec"}, methods)
	require.Equal(t, transform.ActionContinue, events[0].Action)
	require.Equal(t, "ssh_authorization", events[0].RequestTransforms[0].Name)
	for _, e := range events[1:3] {
		require.Equal(t, transform.ActionReject, e.Action)
		require.Equal(t, "ssh_policy", e.RequestTransforms[0].Name)
		require.Equal(t, transform.ActionReject, e.RequestTransforms[0].Action)
	}
	require.Equal(t, transform.ActionContinue, events[3].Action)
	require.Equal(t, "git-upload-pack 'repo'", events[3].Path)
}

// publicOnlySigner offers a public key without holding its private key, as
// anyone who has seen the sandbox's public key could.
type publicOnlySigner struct{ key ssh.PublicKey }

func (s publicOnlySigner) PublicKey() ssh.PublicKey { return s.key }
func (publicOnlySigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errors.New("no private key")
}

func TestAuthorizesOnlyVerifiedSandboxKey(t *testing.T) {
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	other, _ := key(t)
	cases := []struct {
		name   string
		signer ssh.Signer
	}{
		{"unpaired key", other},
		{"paired public key without proof", publicOnlySigner{clientKey.PublicKey()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := &recordAuth{g: backendFixture(t)}
			address, audits := testProxy(t, clientKey, proxyHost, auth.authorize, nil)
			_, err := connect(address, tc.signer, proxyHost)
			require.Error(t, err)

			require.Eventually(t, func() bool { return len(audits.all()) == 1 }, 5*time.Second, 10*time.Millisecond)
			event := audits.all()[0]
			require.Equal(t, "auth", event.Method)
			require.Equal(t, transform.ActionReject, event.Action)
			require.Equal(t, "ssh_authorization", event.RequestTransforms[0].Name)
			require.Empty(t, auth.requests())
		})
	}
}

func TestUpstreamDialHonorsProxyDenyCIDRs(t *testing.T) {
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	guard, err := dnsguard.New(dnsguard.DefaultDenyCIDRs)
	require.NoError(t, err)
	auth := &recordAuth{g: backendFixture(t)}
	address, audits := serveProxy(t, &Server{HostKey: proxyHost, ClientPublicKey: clientKey.PublicKey(), Authorize: auth.authorize, Guard: guard})
	_, err = connect(address, clientKey, proxyHost)
	require.Error(t, err)

	events := audits.all()
	require.Len(t, events, 1)
	require.Equal(t, "auth", events[0].Method)
	require.ErrorContains(t, events[0].Err, "upstream_deny_cidrs")
	require.Len(t, auth.requests(), 1)
}

func TestWrongUpstreamHostKeyIsRejected(t *testing.T) {
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	backendHost, _ := key(t)
	realKey, private := key(t)
	wrongHost, _ := key(t)
	g := grant(t, testBackend(t, backendHost, realKey), wrongHost, private)
	address, audits := testProxy(t, clientKey, proxyHost, func(context.Context, Authorization) (*Grant, error) { return g, nil }, nil)
	_, err := connect(address, clientKey, proxyHost)
	require.Error(t, err)
	require.ErrorContains(t, audits.all()[0].Err, "SSH host identity mismatch")
}

func TestRevocationClosesActiveConnection(t *testing.T) {
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	g := backendFixture(t)
	var denied atomic.Bool
	address, _ := testProxy(t, clientKey, proxyHost, func(context.Context, Authorization) (*Grant, error) {
		if denied.Load() {
			return nil, errAccessDenied
		}
		return g, nil
	}, nil)
	client, err := connect(address, clientKey, proxyHost)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	session, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, session.Start("hold"))
	denied.Store(true)
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("revoked connection stayed open")
	}
}

func TestWstunnelV11Handshake(t *testing.T) {
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	backendHost, _ := key(t)
	realKey, private := key(t)
	target := testBackend(t, backendHost, realKey)
	wsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events/events" || !validTunnelProtocols(r.Header.Get("Sec-WebSocket-Protocol")) {
			http.NotFound(w, r)
			return
		}
		upgrader := ws.HTTPUpgrader{Protocol: func(value string) bool { return value == "v1" }}
		conn, buffered, _, err := upgrader.Upgrade(r, w)
		if err != nil {
			return
		}
		stream := &websocketConn{Conn: conn, reader: buffered}
		defer func() { _ = stream.Close() }()
		upstream, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		defer upstream.Close()
		go func() { _, _ = io.Copy(upstream, stream); _ = upstream.Close() }()
		_, _ = io.Copy(stream, upstream)
	}))
	defer wsServer.Close()
	roots := x509.NewCertPool()
	roots.AddCert(wsServer.Certificate())
	g := grant(t, target, backendHost, private)
	g.Destination = "wss" + strings.TrimPrefix(wsServer.URL, "https") + "/events/events"
	address, _ := testProxy(t, clientKey, proxyHost, func(context.Context, Authorization) (*Grant, error) { return g, nil }, roots)
	client, err := connect(address, clientKey, proxyHost)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	session, err := client.NewSession()
	require.NoError(t, err)
	output, err := session.Output("websocket")
	var exit *ssh.ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, 7, exit.ExitStatus())
	require.Equal(t, "ok:websocket", string(output))

	// Dynamic destinations use the WSS gateway's verified certificate instead
	// of a per-pod SSH pin. The authorizer still approves each exact target.
	tlsGrant := *g
	tlsGrant.HostKey = ""
	tlsGrant.TLSIdentity = true
	route := "ee:" + base64.RawURLEncoding.EncodeToString([]byte(g.Destination))
	for _, test := range []struct {
		name    string
		roots   *x509.CertPool
		allowed bool
	}{
		{"verified TLS", roots, true}, {"untrusted TLS", x509.NewCertPool(), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth := &recordAuth{g: &tlsGrant}
			address, _ := testProxy(t, clientKey, proxyHost, auth.authorize, test.roots)
			client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: route, Auth: []ssh.AuthMethod{ssh.PublicKeys(clientKey)}, HostKeyCallback: ssh.FixedHostKey(proxyHost.PublicKey()), Timeout: time.Second})
			require.Len(t, auth.requests(), 1)
			require.Equal(t, Authorization{Route: "ee", Destination: g.Destination, PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(clientKey.PublicKey())))}, auth.requests()[0])
			if !test.allowed {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			session, err := client.NewSession()
			require.NoError(t, err)
			output, err := session.Output("dynamic")
			var exit *ssh.ExitError
			require.ErrorAs(t, err, &exit)
			require.Equal(t, 7, exit.ExitStatus())
			require.Equal(t, "ok:dynamic", string(output))
		})
	}
}

// validTunnelProtocols checks the wstunnel v11 routing token targets 127.0.0.1:22.
func validTunnelProtocols(header string) bool {
	protocols := strings.Split(header, ",")
	if len(protocols) != 2 {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(protocols[1]), "authorization.bearer."), ".")
	if len(parts) != 3 {
		return false
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var decoded map[string]any
	return json.Unmarshal(claims, &decoded) == nil && decoded["r"] == "127.0.0.1" && decoded["rp"] == float64(22)
}

func TestParseRouteRejectsMalformedTargets(t *testing.T) {
	for _, value := range []string{"", "ee:", "ee:not*base64", "ee:" + strings.Repeat("a", 4096), strings.Repeat("a", 129)} {
		_, _, err := parseRoute(value)
		require.Error(t, err, value)
	}
	route, destination, err := parseRoute("ee:" + base64.RawURLEncoding.EncodeToString([]byte("wss://example.com/x")))
	require.NoError(t, err)
	require.Equal(t, "ee", route)
	require.Equal(t, "wss://example.com/x", destination)
}

func TestValidateGrant(t *testing.T) {
	_, private := key(t)
	host, _ := key(t)
	cases := []struct {
		name   string
		mutate func(*Grant)
		valid  bool
	}{
		{"pinned TCP", func(*Grant) {}, true},
		{"expired", func(g *Grant) { g.ExpiresAt = time.Now().Add(-time.Second) }, false},
		{"lease too long", func(g *Grant) { g.ExpiresAt = time.Now().Add(16 * time.Minute) }, false},
		{"missing host key", func(g *Grant) { g.HostKey = "" }, false},
		{"TLS identity over TCP", func(g *Grant) { g.TLSIdentity, g.HostKey = true, "" }, false},
		{"TLS identity over WSS", func(g *Grant) { g.TLSIdentity, g.HostKey, g.Destination = true, "", "wss://example.com/events" }, true},
		{"TLS identity with host pin", func(g *Grant) { g.TLSIdentity, g.Destination = true, "wss://example.com/events" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := grant(t, "example.com:22", host, private)
			tc.mutate(g)
			if tc.valid {
				require.NoError(t, validateGrant(g))
			} else {
				require.Error(t, validateGrant(g))
			}
		})
	}
}

func TestSameGrant(t *testing.T) {
	decode := func(expiry, generation, credential string) *Grant {
		t.Helper()
		var g Grant
		require.NoError(t, yaml.Unmarshal([]byte(`{"id":"grant","generation":"`+generation+`","expires_at":"`+expiry+`","private_key":{"type":"control_plane","value":"`+credential+`"}}`), &g))
		return &g
	}
	a := decode("2099-01-01T00:00:00.123Z", "one", "same-key")
	b := decode("2099-01-01T00:00:00.123456Z", "one", "same-key")
	require.NotEqual(t, a.PrivateKey.Column, b.PrivateKey.Column, "fixture must shift YAML source positions")
	require.True(t, sameGrant(a, b), "expiry formatting must not revoke an unchanged credential")
	require.NoError(t, yaml.Unmarshal([]byte("value: 'same-key' # harmless comment\ntype: control_plane\n"), &b.PrivateKey))
	require.True(t, sameGrant(a, b), "mapping order, style and comments do not change the credential")
	require.False(t, sameGrant(a, decode("2099-01-01T00:00:00Z", "one", "different-key")), "credential changes must revoke")
	require.False(t, sameGrant(a, decode("2099-01-01T00:00:00Z", "two", "same-key")), "generation changes must revoke")
	b.PrivateKey = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "invalid"}
	require.False(t, sameGrant(a, b), "invalid sources must fail closed")
}

func TestLeaseExpiryInterruptsBlockedRenewal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &Server{RenewalInterval: time.Millisecond, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), Authorize: func(ctx context.Context, _ Authorization) (*Grant, error) { <-ctx.Done(); return nil, ctx.Err() }}
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.renew(ctx, cancel, Authorization{}, &Grant{ExpiresAt: time.Now().Add(30 * time.Millisecond)})
	}()
	select {
	case <-done:
		require.ErrorIs(t, ctx.Err(), context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("blocked renewal outlived lease")
	}
}

func TestHTTPAuthorizationUsesProxyTokenAndDoesNotLeakErrors(t *testing.T) {
	var gotAuth atomic.Value
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		http.Error(w, "test-upstream-secret", http.StatusForbidden)
	}))
	defer controller.Close()
	_, err := HTTPAuthorizer(controller.URL, "test-only-token")(context.Background(), Authorization{Route: "ee"})
	require.ErrorIs(t, err, errAccessDenied)
	require.NotContains(t, err.Error(), "test-upstream-secret")
	require.Equal(t, "Bearer test-only-token", gotAuth.Load())
}

func TestOpenSSHBookkeepingDoesNotDisconnect(t *testing.T) {
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	g := backendFixture(t)
	address, _ := testProxy(t, clientKey, proxyHost, func(context.Context, Authorization) (*Grant, error) { return g, nil }, nil)
	client, err := connect(address, clientKey, proxyHost)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	for _, request := range []string{"keepalive@openssh.com", "tcpip-forward"} {
		ok, _, err := client.SendRequest(request, true, nil)
		require.NoError(t, err)
		require.False(t, ok, "global requests must be refused locally")
	}
	channel, requests, err := client.OpenChannel("session", nil)
	require.NoError(t, err)
	defer func() { _ = channel.Close() }()
	go ssh.DiscardRequests(requests)
	for _, request := range []string{"env", "eow@openssh.com"} {
		_, err := channel.SendRequest(request, false, nil)
		require.NoError(t, err)
	}
	ok, err := channel.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{"after-bookkeeping"}))
	require.NoError(t, err)
	require.True(t, ok)
	output, err := io.ReadAll(channel)
	require.NoError(t, err)
	require.Equal(t, "ok:after-bookkeeping", string(output))
}

func TestKeepalivesDuringServerOutput(t *testing.T) {
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	g := backendFixture(t)
	address, _ := testProxy(t, clientKey, proxyHost, func(context.Context, Authorization) (*Grant, error) { return g, nil }, nil)
	client, err := connect(address, clientKey, proxyHost)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()
	output, err := session.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, session.Start("stream-output"))
	keepalives := make(chan error, 1)
	go func() {
		for range 200 {
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				keepalives <- err
				return
			}
		}
		keepalives <- nil
	}()
	data, err := io.ReadAll(output)
	require.NoError(t, err)
	require.NoError(t, <-keepalives)
	var exit *ssh.ExitError
	require.ErrorAs(t, session.Wait(), &exit)
	require.Equal(t, 7, exit.ExitStatus())
	require.Equal(t, bytes.Repeat([]byte("output"), 1<<21), data)
}
