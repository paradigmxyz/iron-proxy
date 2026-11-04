package sshproxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func startHandshake(t *testing.T, server *Server, clientKey ssh.Signer) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	downstream, err := listener.Accept()
	require.NoError(t, err)
	require.NoError(t, listener.Close())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = client.Close(); _ = downstream.Close() })
	done := make(chan struct{})
	go func() { defer close(done); server.handle(ctx, downstream) }()
	go func() {
		// These fixtures intentionally fail or cancel before authentication completes.
		conn, _, _, err := ssh.NewClientConn(client, "proxy", &ssh.ClientConfig{User: "ee", Auth: []ssh.AuthMethod{ssh.PublicKeys(clientKey)}, HostKeyCallback: ssh.FixedHostKey(server.HostKey.PublicKey())})
		if err == nil {
			_ = conn.Close()
		}
	}()
	return cancel, done
}

func TestHandshakeDeadlineIncludesWSSNegotiation(t *testing.T) {
	for _, stage := range []string{"TLS", "HTTP upgrade"} {
		t.Run(stage, func(t *testing.T) {
			clientKey, _ := key(t)
			proxyHost, _ := key(t)
			backendHost, private := key(t)
			g := grant(t, "unused:22", backendHost, private)
			reached := make(chan struct{})
			server := &Server{HostKey: proxyHost, ClientPublicKey: clientKey.PublicKey(), Authorize: func(context.Context, Authorization) (*Grant, error) { return g, nil }, Guard: &dnsguard.Guard{}, Audit: func(*transform.PipelineResult) {}, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), HandshakeTimeout: 500 * time.Millisecond}
			if stage == "TLS" {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { _ = listener.Close() })
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					close(reached)
					_, _ = io.Copy(io.Discard, conn)
				}()
				g.Destination = "wss://" + listener.Addr().String() + "/events/events"
			} else {
				release := make(chan struct{})
				peer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(reached); <-release }))
				t.Cleanup(func() { close(release); peer.Close() })
				server.TLSRootCAs = peer.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
				g.Destination = "wss" + strings.TrimPrefix(peer.URL, "https") + "/events/events"
			}
			_, done := startHandshake(t, server, clientKey)
			select {
			case <-reached:
			case <-time.After(2 * time.Second):
				t.Fatal("handshake never reached stalled peer")
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("WSS negotiation outlived the handshake deadline")
			}
		})
	}
}

func TestCancellationClosesEstablishedUpstreamDuringSSHHandshake(t *testing.T) {
	clientKey, _ := key(t)
	proxyHost, _ := key(t)
	backendHost, private := key(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	reached, closed := make(chan struct{}), make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(reached)
		_, _ = io.Copy(io.Discard, conn)
		close(closed)
	}()
	g := grant(t, listener.Addr().String(), backendHost, private)
	server := &Server{HostKey: proxyHost, ClientPublicKey: clientKey.PublicKey(), Authorize: func(context.Context, Authorization) (*Grant, error) { return g, nil }, Guard: &dnsguard.Guard{}, Audit: func(*transform.PipelineResult) {}, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), HandshakeTimeout: time.Minute}
	cancel, done := startHandshake(t, server, clientKey)
	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream was not dialed")
	}
	cancel()
	for _, event := range []<-chan struct{}{closed, done} {
		select {
		case <-event:
		case <-time.After(2 * time.Second):
			t.Fatal("cancellation did not close the established upstream and handler")
		}
	}
}
