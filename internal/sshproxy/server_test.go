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
				cfg.AddHostKey(alternateHost)
				cfg.AddHostKey(host)
				server, channels, requests, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer server.Close()
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
					go func() {
						defer stream.Close()
						for req := range reqs {
							switch req.Type {
							case "exec":
								var cmd struct{ Command string }
								if ssh.Unmarshal(req.Payload, &cmd) != nil {
									return
								}
								if err := req.Reply(true, nil); err != nil {
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
					}()
				}
			}()
		}
	}()
	return listener.Addr().String()
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

func testProxy(t *testing.T, clientKey, hostKey ssh.Signer, auth Authorizer, roots *x509.CertPool) (string, *bytes.Buffer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	logs := &safeBuffer{}
	server := &Server{HostKey: hostKey, ClientPublicKey: clientKey.PublicKey(), Authorize: auth, DenyCIDRs: []string{}, TLSRootCAs: roots, Logger: slog.New(slog.NewJSONHandler(logs, nil)), RenewalInterval: 20 * time.Millisecond}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() { cancel(); require.NoError(t, <-done) })
	return listener.Addr().String(), &logs.Buffer
}

type safeBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}

func connect(address string, key, host ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", address, &ssh.ClientConfig{User: "ee", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: time.Second})
}

func TestExecSFTPAndKeyIsolation(t *testing.T) {
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	backendHost, _ := key(t)
	realKey, private := key(t)
	target := testBackend(t, backendHost, realKey)
	g := grant(t, target, backendHost, private)
	address, _ := testProxy(t, clientKey, proxyHost, func(_ context.Context, a Authorization) (*Grant, error) {
		require.Equal(t, "ee", a.Route)
		return g, nil
	}, nil)
	client, err := connect(address, clientKey, proxyHost)
	require.NoError(t, err)
	defer client.Close()
	session, err := client.NewSession()
	require.NoError(t, err)
	output, err := session.Output("test-command")
	var exit *ssh.ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, 7, exit.ExitStatus())
	require.Equal(t, "ok:test-command", string(output))
	files, err := sftp.NewClient(client)
	require.NoError(t, err)
	defer files.Close()
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
	wrong, _ := key(t)
	_, err = connect(address, wrong, proxyHost)
	require.Error(t, err)
	_, err = connect(address, clientKey, backendHost)
	require.Error(t, err)
}

func TestRevocationClosesActiveConnection(t *testing.T) {
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	backendHost, _ := key(t)
	realKey, private := key(t)
	target := testBackend(t, backendHost, realKey)
	g := grant(t, target, backendHost, private)
	var denied atomic.Bool
	address, _ := testProxy(t, clientKey, proxyHost, func(context.Context, Authorization) (*Grant, error) {
		if denied.Load() {
			return nil, errors.New("denied")
		}
		return g, nil
	}, nil)
	client, err := connect(address, clientKey, proxyHost)
	require.NoError(t, err)
	defer client.Close()
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
		if r.URL.Path != "/events/events" {
			http.NotFound(w, r)
			return
		}
		protocols := strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",")
		require.Len(t, protocols, 2)
		token := strings.TrimPrefix(strings.TrimSpace(protocols[1]), "authorization.bearer.")
		parts := strings.Split(token, ".")
		require.Len(t, parts, 3)
		claims, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)
		var decoded map[string]any
		require.NoError(t, json.Unmarshal(claims, &decoded))
		require.Equal(t, "127.0.0.1", decoded["r"])
		require.Equal(t, float64(22), decoded["rp"])
		upgrader := ws.HTTPUpgrader{Protocol: func(value string) bool { return value == "v1" }}
		conn, buffered, _, err := upgrader.Upgrade(r, w)
		if err != nil {
			return
		}
		stream := &websocketConn{Conn: conn, reader: buffered}
		defer stream.Close()
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
	defer client.Close()
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
			address, _ := testProxy(t, clientKey, proxyHost, func(_ context.Context, a Authorization) (*Grant, error) {
				require.Equal(t, "ee", a.Route)
				require.Equal(t, g.Destination, a.Destination)
				return &tlsGrant, nil
			}, test.roots)
			client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: route, Auth: []ssh.AuthMethod{ssh.PublicKeys(clientKey)}, HostKeyCallback: ssh.FixedHostKey(proxyHost.PublicKey()), Timeout: time.Second})
			if !test.allowed {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			defer client.Close()
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

func TestDynamicRoutesAndTLSIdentityValidation(t *testing.T) {
	for _, value := range []string{"ee:", "ee:not*base64", "ee:" + strings.Repeat("a", 4096), strings.Repeat("a", 129)} {
		_, _, err := parseRoute(value)
		require.Error(t, err)
	}
	_, private := key(t)
	host, _ := key(t)
	g := grant(t, "example.com:22", host, private)
	g.TLSIdentity = true
	g.HostKey = ""
	require.Error(t, validateGrant(g), "TLS identity must never be accepted for plain TCP")
	g.Destination = "wss://example.com/events/events"
	require.NoError(t, validateGrant(g))
	g.HostKey = string(ssh.MarshalAuthorizedKey(host.PublicKey()))
	require.Error(t, validateGrant(g), "ambiguous identity modes must fail closed")
}

func TestDeniedIPAndWrongUpstreamHost(t *testing.T) {
	_, err := transport(context.Background(), "tcp://127.0.0.1:22", []string{"127.0.0.0/8"}, nil)
	require.Error(t, err)
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	backendHost, _ := key(t)
	realKey, private := key(t)
	wrongHost, _ := key(t)
	target := testBackend(t, backendHost, realKey)
	g := grant(t, target, wrongHost, private)
	address, _ := testProxy(t, clientKey, proxyHost, func(context.Context, Authorization) (*Grant, error) { return g, nil }, nil)
	_, err = connect(address, clientKey, proxyHost)
	require.Error(t, err)
}

func TestGrantExpiryAndGeneration(t *testing.T) {
	_, private := key(t)
	host, _ := key(t)
	g := grant(t, "example.com:22", host, private)
	require.NoError(t, validateGrant(g))
	other := *g
	other.ExpiresAt = other.ExpiresAt.Add(time.Second)
	require.True(t, sameGrant(g, &other))
	other.Generation = "two"
	require.False(t, sameGrant(g, &other))
	other = *g
	other.ExpiresAt = time.Now().Add(-time.Second)
	require.Error(t, validateGrant(&other))
}

func TestLeaseExpiryInterruptsBlockedRenewal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &Server{RenewalInterval: time.Millisecond, Authorize: func(ctx context.Context, _ Authorization) (*Grant, error) { <-ctx.Done(); return nil, ctx.Err() }}
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
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer test-only-token", r.Header.Get("Authorization"))
		http.Error(w, "test-upstream-secret", http.StatusForbidden)
	}))
	defer controller.Close()
	_, err := HTTPAuthorizer(controller.URL, "test-only-token")(context.Background(), Authorization{Route: "ee"})
	require.Error(t, err)
	require.NotContains(t, err.Error(), "test-upstream-secret")
}

func TestOpenSSHBookkeepingDoesNotDisconnect(t *testing.T) {
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	backendHost, _ := key(t)
	upstreamKey, private := key(t)
	g := grant(t, testBackend(t, backendHost, upstreamKey), backendHost, private)
	address, _ := testProxy(t, clientKey, proxyHost, func(context.Context, Authorization) (*Grant, error) { return g, nil }, nil)
	client, err := connect(address, clientKey, proxyHost)
	require.NoError(t, err)
	defer client.Close()
	for _, request := range []string{"keepalive@openssh.com", "tcpip-forward"} {
		ok, _, err := client.SendRequest(request, true, nil)
		require.NoError(t, err)
		require.False(t, ok, "global requests must be refused locally")
	}
	channel, requests, err := client.OpenChannel("session", nil)
	require.NoError(t, err)
	defer channel.Close()
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
	backendHost, _ := key(t)
	upstreamKey, private := key(t)
	g := grant(t, testBackend(t, backendHost, upstreamKey), backendHost, private)
	address, _ := testProxy(t, clientKey, proxyHost, func(context.Context, Authorization) (*Grant, error) { return g, nil }, nil)
	client, err := connect(address, clientKey, proxyHost)
	require.NoError(t, err)
	defer client.Close()
	session, err := client.NewSession()
	require.NoError(t, err)
	defer session.Close()
	output, err := session.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, session.Start("stream-output"))
	keepalives := make(chan error, 1)
	go func() {
		for range 200 {
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
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
