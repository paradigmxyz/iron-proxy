package sshproxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

func TestOptionalListenerLifecycle(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	server, listener, err := LoadFromNode(context.Background(), yaml.Node{}, logger)
	require.NoError(t, err)
	require.Nil(t, server)
	require.Nil(t, listener)

	_, private := key(t)
	client, _ := key(t)
	t.Setenv("SSH_STARTUP_TEST_TOKEN", "synthetic-token")
	data, err := json.Marshal(map[string]any{
		"listen": "127.0.0.1:0", "host_key": map[string]string{"type": "control_plane", "value": string(private)},
		"client_public_key": string(ssh.MarshalAuthorizedKey(client.PublicKey())), "authorize_url": "http://127.0.0.1/authorize", "token_env": "SSH_STARTUP_TEST_TOKEN",
	})
	require.NoError(t, err)
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal(data, &node))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, listener, err = LoadFromNode(ctx, node, logger)
	require.NoError(t, err)
	defer listener.Close()
	require.NotEmpty(t, server.DenyCIDRs)
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("listener did not stop with the proxy context")
	}

	t.Setenv("SSH_STARTUP_TEST_TOKEN", "")
	server, listener, err = LoadFromNode(context.Background(), node, logger)
	require.ErrorContains(t, err, "token unavailable")
	require.Nil(t, server)
	require.Nil(t, listener)
}
