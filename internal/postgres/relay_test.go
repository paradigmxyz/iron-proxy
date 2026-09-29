package postgres

import (
	"encoding/binary"
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

	backend := newClientBackend(relayClient)
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

func TestRelayClosesConnectionForOversizedFrontendMessage(t *testing.T) {
	client, relayClient := net.Pipe()
	relayUpstream, upstream := net.Pipe()
	clientClosed := false
	upstreamClosed := false
	t.Cleanup(func() {
		if !clientClosed {
			require.NoError(t, client.Close())
		}
		if !upstreamClosed {
			require.NoError(t, upstream.Close())
		}
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := newRelay(
		relayClient,
		relayUpstream,
		newClientBackend(relayClient),
		pgproto3.NewFrontend(relayUpstream, relayUpstream),
		&Upstream{},
		logger,
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.run()
	}()

	header := make([]byte, 5)
	header[0] = 'Q'
	// The protocol length includes its own four bytes, but not the message type.
	binary.BigEndian.PutUint32(header[1:], uint32(maxFrontendMessageBodyLen+5))
	_, err := client.Write(header)
	require.NoError(t, err)

	require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = client.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)

	select {
	case <-done:
	case <-time.After(time.Second):
		require.FailNow(t, "relay did not stop after oversized frontend message")
	}

	require.NoError(t, client.Close())
	clientClosed = true
	require.NoError(t, upstream.Close())
	upstreamClosed = true
}

func TestRelayPreservesUpstreamTransactionStateOnReject(t *testing.T) {
	statuses := []struct {
		name  string
		value byte
	}{
		{name: "transaction", value: 'T'},
		{name: "failed transaction", value: 'E'},
	}
	protocols := []struct {
		name string
		send func(*pgproto3.Frontend) error
		sync bool
	}{
		{
			name: "simple query",
			send: func(client *pgproto3.Frontend) error {
				client.Send(&pgproto3.Query{String: "SET ROLE other_role"})
				return client.Flush()
			},
		},
		{
			name: "extended query",
			send: func(client *pgproto3.Frontend) error {
				client.Send(&pgproto3.Parse{Query: "SET ROLE other_role"})
				return client.Flush()
			},
			sync: true,
		},
	}

	for _, status := range statuses {
		for _, protocol := range protocols {
			t.Run(status.name+"/"+protocol.name, func(t *testing.T) {
				client, relayClient := net.Pipe()
				relayUpstream, upstream := net.Pipe()
				clientClosed := false
				upstreamClosed := false
				t.Cleanup(func() {
					if !clientClosed {
						require.NoError(t, client.Close())
					}
					if !upstreamClosed {
						require.NoError(t, upstream.Close())
					}
				})

				logger := slog.New(slog.NewTextHandler(io.Discard, nil))
				r := newRelay(
					relayClient,
					relayUpstream,
					newClientBackend(relayClient),
					pgproto3.NewFrontend(relayUpstream, relayUpstream),
					&Upstream{},
					logger,
				)

				done := make(chan struct{})
				go func() {
					defer close(done)
					r.run()
				}()

				upstreamProtocol := pgproto3.NewBackend(upstream, upstream)
				upstreamProtocol.Send(&pgproto3.ReadyForQuery{TxStatus: status.value})
				require.NoError(t, upstreamProtocol.Flush())

				clientProtocol := pgproto3.NewFrontend(client, client)
				msg, err := clientProtocol.Receive()
				require.NoError(t, err)
				ready, ok := msg.(*pgproto3.ReadyForQuery)
				require.True(t, ok)
				require.Equal(t, status.value, ready.TxStatus)

				require.NoError(t, protocol.send(clientProtocol))

				msg, err = clientProtocol.Receive()
				require.NoError(t, err)
				_, ok = msg.(*pgproto3.ErrorResponse)
				require.True(t, ok)
				if protocol.sync {
					clientProtocol.Send(&pgproto3.Sync{})
					require.NoError(t, clientProtocol.Flush())
				}

				msg, err = clientProtocol.Receive()
				require.NoError(t, err)
				ready, ok = msg.(*pgproto3.ReadyForQuery)
				require.True(t, ok)
				require.Equal(t, status.value, ready.TxStatus)

				require.NoError(t, client.Close())
				clientClosed = true
				select {
				case <-done:
				case <-time.After(time.Second):
					require.FailNow(t, "relay did not stop")
				}
				require.NoError(t, upstream.Close())
				upstreamClosed = true
			})
		}
	}
}
