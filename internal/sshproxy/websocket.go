package sshproxy

import (
	"errors"
	"io"
	"net"
	"sync"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// websocketConn matches wstunnel v11's default unmasked framing on both legs.
// TLS still authenticates and encrypts the external transport.
type websocketConn struct {
	net.Conn
	reader     io.Reader
	remaining  int64
	fragmented bool
	writeMu    sync.Mutex
}

func (c *websocketConn) Write(data []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := wsutil.WriteServerBinary(c.Conn, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *websocketConn) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	for c.remaining == 0 {
		h, err := ws.ReadHeader(c.reader)
		if err != nil {
			return 0, err
		}
		if h.Masked || h.Rsv != 0 || h.Length < 0 || h.Length > 1<<20 {
			return 0, errors.New("invalid wstunnel frame")
		}
		switch h.OpCode {
		case ws.OpBinary:
			if c.fragmented {
				return 0, errors.New("invalid wstunnel fragmentation")
			}
			c.fragmented = !h.Fin
			c.remaining = h.Length
		case ws.OpContinuation:
			if !c.fragmented {
				return 0, errors.New("unexpected wstunnel continuation")
			}
			c.fragmented = !h.Fin
			c.remaining = h.Length
		case ws.OpPing, ws.OpPong, ws.OpClose:
			if !h.Fin || h.Length > 125 {
				return 0, errors.New("invalid wstunnel control frame")
			}
			payload := make([]byte, int(h.Length))
			if _, err = io.ReadFull(c.reader, payload); err != nil {
				return 0, err
			}
			if h.OpCode == ws.OpClose {
				return 0, io.EOF
			}
			if h.OpCode == ws.OpPing {
				c.writeMu.Lock()
				err = wsutil.WriteServerMessage(c.Conn, ws.OpPong, payload)
				c.writeMu.Unlock()
				if err != nil {
					return 0, err
				}
			}
		default:
			return 0, errors.New("unsupported wstunnel frame")
		}
	}
	if int64(len(data)) > c.remaining {
		data = data[:int(c.remaining)]
	}
	n, err := c.reader.Read(data)
	c.remaining -= int64(n)
	return n, err
}
