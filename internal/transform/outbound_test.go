package transform

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetOutboundDialer_InstallsAndRestores(t *testing.T) {
	original := http.DefaultClient.Transport
	t.Cleanup(func() {
		SetOutboundDialer(nil)
		require.Equal(t, original, http.DefaultClient.Transport)
	})

	called := false
	SetOutboundDialer(func(context.Context, string, string) (net.Conn, error) {
		called = true
		server, client := net.Pipe()
		require.NoError(t, server.Close())
		return client, nil
	})

	require.NotNil(t, OutboundDialer())
	require.NotNil(t, http.DefaultClient.Transport)

	conn, err := NewOutboundTransport().DialContext(context.Background(), "tcp", "example.com:443")
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.True(t, called)

	SetOutboundDialer(nil)
	require.Nil(t, OutboundDialer())
	require.Equal(t, original, http.DefaultClient.Transport)
}
