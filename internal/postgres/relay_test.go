package postgres

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/require"
)

func TestRelayRejectsFunctionCall(t *testing.T) {
	client, relayClient := net.Pipe()
	relayUpstream, upstream := net.Pipe()
	clientClosed := false
	t.Cleanup(func() {
		if !clientClosed {
			require.NoError(t, client.Close())
		}
		require.NoError(t, relayClient.Close())
		require.NoError(t, relayUpstream.Close())
		require.NoError(t, upstream.Close())
	})

	backend := pgproto3.NewBackend(relayClient, relayClient)
	frontend := pgproto3.NewFrontend(relayUpstream, relayUpstream)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := newRelay(relayClient, relayUpstream, backend, frontend, &Upstream{}, logger)
	r.txStatus = 'T'

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.clientToServer()
	}()

	clientProtocol := pgproto3.NewFrontend(client, client)
	clientProtocol.Send(&pgproto3.FunctionCall{
		Function:         1,
		ArgFormatCodes:   []uint16{0},
		Arguments:        [][]byte{[]byte("role"), []byte("other_role"), []byte("false")},
		ResultFormatCode: 0,
	})
	require.NoError(t, clientProtocol.Flush())

	msg, err := clientProtocol.Receive()
	require.NoError(t, err)
	pgErr, ok := msg.(*pgproto3.ErrorResponse)
	require.True(t, ok)
	require.Equal(t, "0A000", pgErr.Code)
	require.Contains(t, pgErr.Message, "FunctionCall")

	msg, err = clientProtocol.Receive()
	require.NoError(t, err)
	ready, ok := msg.(*pgproto3.ReadyForQuery)
	require.True(t, ok)
	require.Equal(t, byte('T'), ready.TxStatus)

	require.NoError(t, upstream.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = upstream.Read(make([]byte, 1))
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout())
	require.NoError(t, upstream.SetReadDeadline(time.Time{}))

	clientProtocol.Send(&pgproto3.Query{String: "SELECT 1"})
	require.NoError(t, clientProtocol.Flush())
	upstreamProtocol := pgproto3.NewBackend(upstream, upstream)
	upstreamMsg, err := upstreamProtocol.Receive()
	require.NoError(t, err)
	query, ok := upstreamMsg.(*pgproto3.Query)
	require.True(t, ok)
	require.Equal(t, "SELECT 1", query.String)

	require.NoError(t, client.Close())
	clientClosed = true
	select {
	case <-done:
	case <-time.After(time.Second):
		require.FailNow(t, "client-to-server relay did not stop")
	}
}
