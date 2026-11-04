package sshproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/transform"
)

type testEnv struct {
	addr         string
	upstreamAddr string
	sandbox      ssh.Signer
	hostKey      ssh.PublicKey
	authorized   atomic.Int32
	upstreamHits atomic.Int32
	mu           sync.Mutex
	audits       []*transform.PipelineResult
}

func (e *testEnv) events() []*transform.PipelineResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*transform.PipelineResult(nil), e.audits...)
}

func newSigner(t *testing.T) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer, priv
}

// startEnv runs a real upstream SSH server and the proxy in front of it.
func startEnv(t *testing.T, guard *dnsguard.Guard) *testEnv {
	t.Helper()
	env := &testEnv{}
	env.sandbox, _ = newSigner(t)
	proxyHost, _ := newSigner(t)
	env.hostKey = proxyHost.PublicKey()
	upstreamHost, _ := newSigner(t)
	credential, credentialKey := newSigner(t)

	pemBlock, err := ssh.MarshalPrivateKey(credentialKey, "")
	require.NoError(t, err)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0o600))
	var source yaml.Node
	require.NoError(t, yaml.Unmarshal(fmt.Appendf(nil, "type: file\npath: %s\n", keyPath), &source))

	upstreamConfig := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(key.Marshal(), credential.PublicKey().Marshal()) {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	upstreamConfig.AddHostKey(upstreamHost)
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = upstream.Close() }) // closing an unused listener cannot fail meaningfully
	env.upstreamAddr = upstream.Addr().String()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			env.upstreamHits.Add(1)
			go serveUpstream(conn, upstreamConfig)
		}
	}()

	server := &Server{
		HostKey:         proxyHost,
		ClientPublicKey: env.sandbox.PublicKey(),
		Guard:           guard,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Audit: func(r *transform.PipelineResult) {
			env.mu.Lock()
			defer env.mu.Unlock()
			env.audits = append(env.audits, r)
		},
		Authorize: func(_ context.Context, a Authorization) (*Grant, error) {
			env.authorized.Add(1)
			return &Grant{
				ID: "g1", Principal: "alice", Generation: "1", Username: "git",
				Destination: "tcp://" + env.upstreamAddr,
				HostKey:     string(ssh.MarshalAuthorizedKey(upstreamHost.PublicKey())),
				PrivateKey:  *source.Content[0],
				ExpiresAt:   time.Now().Add(time.Minute),
			}, nil
		},
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	env.addr = listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	return env
}

// serveUpstream answers exec requests with the command it received.
func serveUpstream(conn net.Conn, config *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return // handshake failures are the expected outcome in some tests
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range chReqs {
				var exec struct{ Command string }
				if req.Type != "exec" || ssh.Unmarshal(req.Payload, &exec) != nil {
					_ = req.Reply(false, nil) // test peer; failures surface in the client
					continue
				}
				_ = req.Reply(true, nil)
				_, _ = fmt.Fprintf(ch, "ran: %s", exec.Command)
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				_ = ch.Close()
			}
		}()
	}
}

func dial(env *testEnv, signer ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", env.addr, &ssh.ClientConfig{
		User:            "github",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(env.hostKey),
		Timeout:         5 * time.Second,
	})
}

func TestServerProxiesExecAndRefusesOtherCapabilities(t *testing.T) {
	env := startEnv(t, &dnsguard.Guard{})
	client, err := dial(env, env.sandbox)
	require.NoError(t, err)
	defer client.Close()

	refused, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, refused.RequestPty("xterm", 24, 80, nil))
	require.NoError(t, refused.Close())
	_, err = client.Dial("tcp", "example.com:80")
	require.Error(t, err)

	// Refusals do not tear down the connection.
	session, err := client.NewSession()
	require.NoError(t, err)
	out, err := session.Output("git-upload-pack 'repo'")
	require.NoError(t, err)
	require.Equal(t, "ran: git-upload-pack 'repo'", string(out))

	events := env.events()
	methods := make([]string, len(events))
	for i, e := range events {
		methods[i] = e.Method
		require.Equal(t, transform.ModeSSH, e.Mode)
		require.Equal(t, env.upstreamAddr, e.Host)
		require.Len(t, e.RequestTransforms, 1)
		require.Equal(t, "alice", e.RequestTransforms[0].Annotations["principal"])
		require.Equal(t, "g1", e.RequestTransforms[0].Annotations["grant_id"])
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

func TestServerAuthorizesOnlyVerifiedSandboxKey(t *testing.T) {
	other, _ := newSigner(t)
	cases := []struct {
		name   string
		signer func(*testEnv) ssh.Signer
	}{
		{"unpaired key", func(*testEnv) ssh.Signer { return other }},
		{"paired public key without proof", func(e *testEnv) ssh.Signer { return publicOnlySigner{e.sandbox.PublicKey()} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := startEnv(t, &dnsguard.Guard{})
			_, err := dial(env, tc.signer(env))
			require.Error(t, err)

			require.Eventually(t, func() bool { return len(env.events()) == 1 }, 5*time.Second, 10*time.Millisecond)
			event := env.events()[0]
			require.Equal(t, "auth", event.Method)
			require.Equal(t, transform.ActionReject, event.Action)
			require.Equal(t, "ssh_authorization", event.RequestTransforms[0].Name)
			require.Zero(t, env.authorized.Load())
			require.Zero(t, env.upstreamHits.Load())
		})
	}
}

func TestServerUpstreamDialHonorsProxyDenyCIDRs(t *testing.T) {
	guard, err := dnsguard.New(dnsguard.DefaultDenyCIDRs)
	require.NoError(t, err)
	env := startEnv(t, guard)
	_, err = dial(env, env.sandbox)
	require.Error(t, err)

	events := env.events()
	require.Len(t, events, 1)
	require.Equal(t, "auth", events[0].Method)
	require.ErrorContains(t, events[0].Err, "upstream_deny_cidrs")
	require.Equal(t, int32(1), env.authorized.Load())
	require.Zero(t, env.upstreamHits.Load())
}
