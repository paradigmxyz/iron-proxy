package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSameAuthority(t *testing.T) {
	cases := []struct {
		name          string
		inner, target string
		scheme        string
		want          bool
	}{
		{"exact host:port", "example.com:443", "example.com:443", "https", true},
		{"implicit https port", "example.com", "example.com:443", "https", true},
		{"implicit http port", "example.com", "example.com:80", "http", true},
		{"case insensitive", "Example.COM", "example.com:443", "https", true},
		{"nonstandard port match", "example.com:8443", "example.com:8443", "https", true},
		{"different host", "blocked.example.com", "allowed.example.com:443", "https", false},
		{"same host different port", "example.com:8443", "example.com:443", "https", false},
		{"implicit vs nonstandard", "example.com", "example.com:8443", "https", false},
		{"ipv6 implicit port", "[2001:db8::1]", "[2001:db8::1]:443", "https", true},
		{"ipv6 both ports", "[2001:db8::1]:443", "[2001:db8::1]:443", "https", true},
		{"ipv6 loopback", "[::1]", "[::1]:443", "https", true},
		{"ipv6 different host", "[2001:db8::2]", "[2001:db8::1]:443", "https", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, sameAuthority(tc.inner, tc.target, tc.scheme))
		})
	}
}

// A tunnel authorized for one host must not carry a request addressed to
// another, even when that request's SNI and Host agree with each other. The
// matching case (CONNECT to host:443, inner Host without a port) is covered by
// TestTunnel_CONNECT_HTTPS_MITM.
func TestTunnel_CONNECT_RejectsHostMismatch(t *testing.T) {
	p, tunnelAddr, caPool := startTunnelProxy(t, nil)

	// The request must be refused before any upstream dial.
	p.transport = &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unexpected upstream dial")
		},
	}

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT allowed.example.com:443 HTTP/1.1\r\nHost: allowed.example.com:443\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	tlsConn := tls.Client(conn, &tls.Config{RootCAs: caPool, ServerName: "other.example.com"})
	defer func() { _ = tlsConn.Close() }()
	require.NoError(t, tlsConn.Handshake())

	req, err := http.NewRequest(http.MethodGet, "https://other.example.com/", nil)
	require.NoError(t, err)
	require.NoError(t, req.Write(tlsConn))

	inner, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	require.NoError(t, err)
	defer inner.Body.Close()
	require.Equal(t, http.StatusBadRequest, inner.StatusCode)
}
