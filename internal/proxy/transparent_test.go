package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// fakeLocalAddrConn overrides LocalAddr so an ordinary TCP connection can stand
// in for a TPROXY-accepted one. With TPROXY the kernel publishes the original
// destination as the accepted socket's local address; that is exactly what
// handleTransparent reads, so faking it keeps the test hermetic — real TPROXY
// needs NET_ADMIN and kernel policy routing, which a unit test must not require.
type fakeLocalAddrConn struct {
	net.Conn
	local net.Addr
}

func (c fakeLocalAddrConn) LocalAddr() net.Addr { return c.local }

// nonTCPAddr is a LocalAddr that is not a *net.TCPAddr.
type nonTCPAddr struct{}

func (nonTCPAddr) Network() string { return "unix" }
func (nonTCPAddr) String() string  { return "/tmp/not-a-socket" }

// transparentHarness wires a Proxy to a plain listener whose accepted
// connections report the "original destination" the test chose, mirroring what
// the kernel does for a TPROXY'd connection.
type transparentHarness struct {
	proxy  *Proxy
	addr   string
	pool   *x509.CertPool
	target atomic.Pointer[net.TCPAddr]
}

// setTarget records the destination the next accepted connection should appear
// to have been addressed to. Must be called from the test goroutine before the
// connection is dialed (the accept loop only ever Loads).
func (h *transparentHarness) setTarget(t *testing.T, addr string) {
	t.Helper()
	ta, err := net.ResolveTCPAddr("tcp", addr)
	require.NoError(t, err)
	h.target.Store(ta)
}

func startTransparentProxy(t *testing.T, transforms []transform.Transformer) *transparentHarness {
	t.Helper()

	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)

	pipeline := transform.NewPipeline(transforms, transform.BodyLimits{}, testLogger())
	holder := transform.NewPipelineHolder(pipeline)
	p := New(Options{
		HTTPAddr:  "127.0.0.1:0",
		HTTPSAddr: "127.0.0.1:0",
		CertCache: cache,
		Pipeline:  holder,
		Logger:    testLogger(),
	})

	h := &transparentHarness{proxy: p}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	h.addr = ln.Addr().String()
	p.transparentListener = ln

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Default to an unspecified address: a TPROXY'd socket that never
			// received a destination looks exactly like this.
			local := h.target.Load()
			if local == nil {
				local = &net.TCPAddr{}
			}
			go p.handleTransparent(fakeLocalAddrConn{Conn: conn, local: local})
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		close(p.transparentDone)
	})

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	h.pool = pool
	return h
}

func TestTransparentTarget(t *testing.T) {
	cases := []struct {
		name    string
		local   net.Addr
		want    string
		wantErr bool
	}{
		{
			name:  "ipv4 original destination is read off the socket",
			local: &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 8443},
			want:  "203.0.113.7:8443",
		},
		{
			name:  "ipv6 original destination is preserved",
			local: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8006},
			want:  "[2001:db8::1]:8006",
		},
		{
			name:    "unspecified address means tproxy never published a destination",
			local:   &net.TCPAddr{},
			wantErr: true,
		},
		{
			name:    "non-tcp local address is rejected",
			local:   nonTCPAddr{},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := transparentTarget(fakeLocalAddrConn{local: tc.local})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// requireServedNothing asserts the proxy closed the connection without sending
// anything back. The exact error differs by timing — a clean close surfaces as
// io.EOF, while closing with unread client data in the buffer sends RST and
// surfaces as ECONNRESET — so only "zero bytes, and an error" is invariant.
func requireServedNothing(t *testing.T, conn net.Conn) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, err := conn.Read(make([]byte, 1))
	require.Error(t, err)
	require.Zero(t, n)
}

// A transparent plain-HTTP connection must be proxied without any client-side
// proxy handshake: the client believes it is talking to the destination.
func TestTransparent_PlainHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Transparent", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from transparent")
	}))
	defer upstream.Close()

	h := startTransparentProxy(t, nil)
	h.setTarget(t, upstream.Listener.Addr().String())

	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// No CONNECT: the request is sent as if straight to the origin.
	_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.Listener.Addr().String())
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "true", resp.Header.Get("X-Transparent"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from transparent", string(body))
}

// A transparent TLS connection must be MITM'd, with a leaf minted for the SNI
// even though the destination was recovered as an IP:port.
func TestTransparent_TLSMITM(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from transparent tls")
	}))
	defer upstream.Close()

	h := startTransparentProxy(t, nil)

	upstreamAddr := upstream.Listener.Addr().String()
	h.proxy.transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}
	h.setTarget(t, upstreamAddr)

	const fakeHost = "tproxy.example.com"

	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{RootCAs: h.pool, ServerName: fakeHost})
	defer func() { _ = tlsConn.Close() }()
	require.NoError(t, tlsConn.Handshake())

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", fakeHost), nil)
	require.NoError(t, err)
	require.NoError(t, req.Write(tlsConn))

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from transparent tls", string(body))
}

// Transparency must not bypass policy: a rejected destination is closed before
// any client byte is echoed back, the same default-deny gate as the tunnel.
func TestTransparent_TransformReject(t *testing.T) {
	h := startTransparentProxy(t, []transform.Transformer{&rejectTransform{}})
	h.setTarget(t, "example.com:80")

	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// The decision happens on accept, so no request is needed to trigger it.
	requireServedNothing(t, conn)
}

// Without an original destination (no TPROXY rule / policy route) the proxy
// must refuse the connection rather than serve it as 0.0.0.0.
func TestTransparent_NoOriginalDestination(t *testing.T) {
	h := startTransparentProxy(t, nil)
	// Deliberately leave the target unset: LocalAddr is unspecified.

	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)

	requireServedNothing(t, conn)
}
