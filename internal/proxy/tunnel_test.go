package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func startTunnelProxy(t *testing.T, transforms []transform.Transformer) (*Proxy, string, *x509.CertPool) {
	t.Helper()

	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)

	pipeline := transform.NewPipeline(transforms, transform.BodyLimits{}, testLogger())
	holder := transform.NewPipelineHolder(pipeline)
	p := New(Options{
		HTTPAddr:   "127.0.0.1:0",
		HTTPSAddr:  "127.0.0.1:0",
		TunnelAddr: "127.0.0.1:0",
		CertCache:  cache,
		Pipeline:   holder,
		Logger:     testLogger(),
	})

	// Start tunnel listener
	tunnelLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tunnelAddr := tunnelLn.Addr().String()
	p.tunnelListener = tunnelLn

	go func() {
		for {
			conn, err := tunnelLn.Accept()
			if err != nil {
				return
			}
			go p.handleTunnel(conn)
		}
	}()

	t.Cleanup(func() {
		tunnelLn.Close()
		close(p.tunnelDone)
	})

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return p, tunnelAddr, pool
}

func TestTunnel_CONNECT_HTTP(t *testing.T) {
	// Start an upstream HTTP server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Tunnel", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from tunnel")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	// Send CONNECT request
	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := upstream.Listener.Addr().String()
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)

	// Read 200 Connection Established
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Now send an HTTP request through the tunnel (raw tunnel, not MITM)
	_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)

	resp2, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp2.Body.Close()

	require.Equal(t, http.StatusOK, resp2.StatusCode)
	require.Equal(t, "true", resp2.Header.Get("X-Tunnel"))

	body, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from tunnel", string(body))
}

func TestTunnel_CONNECT_HTTPS_MITM(t *testing.T) {
	// Start an upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Empty(t, r.Header.Get("Content-Length"), "GET request over HTTPS MITM tunnel should not have Content-Length")
		require.Empty(t, r.TransferEncoding, "GET request over HTTPS MITM tunnel should not have Transfer-Encoding")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from tls tunnel")
	}))
	defer upstream.Close()

	p, tunnelAddr, caPool := startTunnelProxy(t, nil)

	// Override transport to route to the upstream
	upstreamAddr := upstream.Listener.Addr().String()
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	const fakeHost = "mitm.example.com"

	// Send CONNECT to port 443 (triggers MITM)
	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", fakeHost, fakeHost)
	require.NoError(t, err)

	// Read 200 Connection Established
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Now do TLS handshake on the tunneled connection
	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    caPool,
		ServerName: fakeHost,
	})
	defer func() { _ = tlsConn.Close() }()

	err = tlsConn.Handshake()
	require.NoError(t, err)

	// Send HTTP request through the TLS tunnel
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", fakeHost), nil)
	require.NoError(t, err)

	err = req.Write(tlsConn)
	require.NoError(t, err)

	tlsBr := bufio.NewReader(tlsConn)
	resp2, err := http.ReadResponse(tlsBr, req)
	require.NoError(t, err)
	defer resp2.Body.Close()

	require.Equal(t, http.StatusOK, resp2.StatusCode)
	require.False(t, resp2.Close)

	body, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from tls tunnel", string(body))

	req2, err := http.NewRequest("GET", fmt.Sprintf("https://%s/again", fakeHost), nil)
	require.NoError(t, err)

	err = req2.Write(tlsConn)
	require.NoError(t, err)

	resp3, err := http.ReadResponse(tlsBr, req2)
	require.NoError(t, err)
	defer resp3.Body.Close()

	require.Equal(t, http.StatusOK, resp3.StatusCode)
	body, err = io.ReadAll(resp3.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from tls tunnel", string(body))
}

func TestTunnel_HTTPProxyAbsoluteForm(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/test?x=1", r.RequestURI)
		w.Header().Set("X-Tunnel-HTTP", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from http proxy")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	proxyURL, err := url.Parse("http://" + tunnelAddr)
	require.NoError(t, err)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport}
	resp, err := client.Get(upstream.URL + "/test?x=1")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "true", resp.Header.Get("X-Tunnel-HTTP"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from http proxy", string(body))
}

func TestTunnel_HTTPProxyRejectsAbsoluteFormHTTPS(t *testing.T) {
	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "GET https://example.com/test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestTunnel_SOCKS5_HTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Socks", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from socks5")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	upstreamHost, upstreamPortStr, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	// SOCKS5 auth negotiation: version 5, 1 method (no auth)
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)

	// Read auth response
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), authResp[0])
	require.Equal(t, byte(0x00), authResp[1])

	// SOCKS5 connect request: IPv4
	ip := net.ParseIP(upstreamHost).To4()
	require.NotNil(t, ip)

	var port uint16
	_, err = fmt.Sscanf(upstreamPortStr, "%d", &port)
	require.NoError(t, err)

	connectReq := []byte{0x05, 0x01, 0x00, 0x01} // ver, cmd=connect, rsv, atyp=IPv4
	connectReq = append(connectReq, ip...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	connectReq = append(connectReq, portBuf...)

	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	// Read connect response
	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), connectResp[0]) // version
	require.Equal(t, byte(0x00), connectResp[1]) // success

	// Now send HTTP through the tunnel
	target := upstream.Listener.Addr().String()
	_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "true", resp.Header.Get("X-Socks"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from socks5", string(body))
}

func TestTunnel_SOCKS5_DomainName(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "domain ok")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, upstreamPortStr, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	var port uint16
	_, err = fmt.Sscanf(upstreamPortStr, "%d", &port)
	require.NoError(t, err)

	// Auth negotiation
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)

	// Connect with domain name type (0x03) pointing to 127.0.0.1
	domain := "127.0.0.1" // using IP as "domain" for test simplicity
	connectReq := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	connectReq = append(connectReq, []byte(domain)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	connectReq = append(connectReq, portBuf...)

	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x00), connectResp[1]) // success

	// Send HTTP request
	target := upstream.Listener.Addr().String()
	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestTunnel_SOCKS5_NoAuth_Required(t *testing.T) {
	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Offer only username/password auth (0x02), no no-auth
	_, err = conn.Write([]byte{0x05, 0x01, 0x02})
	require.NoError(t, err)

	resp := make([]byte, 2)
	_, err = io.ReadFull(conn, resp)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), resp[0])
	require.Equal(t, byte(0xFF), resp[1]) // no acceptable methods
}

func TestTunnel_TransformReject(t *testing.T) {
	// Use a transform that rejects everything
	rejecter := &rejectTransform{}

	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{rejecter})

	// Test CONNECT rejection
	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	err = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	require.NoError(t, err)
	_, err = br.Peek(1)
	require.ErrorIs(t, err, io.EOF)
}

func TestTunnel_CONNECTHeadersAndRejectResponse(t *testing.T) {
	auth := &connectHeaderAuthTransform{}

	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{auth})

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	require.Equal(t, `Basic realm="proxy"`, resp.Header.Get("Proxy-Authenticate"))
	require.Equal(t, "example.com:443", auth.lastTarget)

	conn2, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn2.Close()

	_, err = fmt.Fprintf(conn2, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic ok\r\n\r\n")
	require.NoError(t, err)

	resp2, err := http.ReadResponse(bufio.NewReader(conn2), nil)
	require.NoError(t, err)
	_ = resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestTunnelInfoPropagatesToInnerTransforms(t *testing.T) {
	seen := make(chan *transform.TunnelInfo, 1)
	tunnelInfoTransform := &tunnelInfoTransform{seen: seen}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{tunnelInfoTransform})
	target := upstream.Listener.Addr().String()

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)

	resp2, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)

	select {
	case info := <-seen:
		require.Equal(t, target, info.Target)
		require.Len(t, info.RequestTransforms, 1)
		require.Equal(t, "tunnel-info", info.RequestTransforms[0].Name)
		require.Equal(t, "alice", info.RequestTransforms[0].Annotations["user_id"])
	case <-time.After(2 * time.Second):
		t.Fatal("inner transform did not receive tunnel info")
	}
}

func TestTunnel_SOCKS5_TransformReject(t *testing.T) {
	rejecter := &rejectTransform{}

	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{rejecter})

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Auth
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)

	// Connect to some target
	connectReq := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50} // 127.0.0.1:80
	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x02), connectResp[1]) // connection not allowed
}

// rejectTransform rejects all requests.
type rejectTransform struct{}

func (r *rejectTransform) Name() string { return "rejecter" }

func (r *rejectTransform) TransformRequest(_ context.Context, _ *transform.TransformContext, _ *http.Request) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionReject}, nil
}

func (r *rejectTransform) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

type connectHeaderAuthTransform struct {
	lastTarget string
}

func (c *connectHeaderAuthTransform) Name() string { return "connect-auth" }

func (c *connectHeaderAuthTransform) TransformRequest(_ context.Context, _ *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if req.Method != http.MethodConnect {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	c.lastTarget = req.Host
	if req.Header.Get("Proxy-Authorization") == "Basic ok" {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	return &transform.TransformResult{
		Action: transform.ActionReject,
		Response: &http.Response{
			StatusCode: http.StatusProxyAuthRequired,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Proxy-Authenticate": []string{`Basic realm="proxy"`}},
			Body:       http.NoBody,
		},
	}, nil
}

func (c *connectHeaderAuthTransform) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

type tunnelInfoTransform struct {
	seen chan<- *transform.TunnelInfo
}

func (t *tunnelInfoTransform) Name() string { return "tunnel-info" }

func (t *tunnelInfoTransform) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if req.Method == http.MethodConnect {
		tctx.Annotate("user_id", "alice")
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	if tctx.Tunnel != nil {
		select {
		case t.seen <- tctx.Tunnel:
		default:
		}
	}
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (t *tunnelInfoTransform) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// startWebSocketEchoUpstream starts a raw TCP server that accepts a single
// connection, answers a WebSocket upgrade request with 101 Switching
// Protocols, then echoes all subsequent bytes back to the client.
func startWebSocketEchoUpstream(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}

		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n\r\n"
		if _, err := conn.Write([]byte(resp)); err != nil {
			return
		}

		buf := make([]byte, 4096)
		for {
			n, err := br.Read(buf)
			if err != nil {
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	return ln.Addr().String()
}

// wsUpgradeAndEcho sends a WebSocket upgrade request for target over conn,
// verifies the 101 response, then checks that payload bytes echo back.
func wsUpgradeAndEcho(t *testing.T, conn net.Conn, br *bufio.Reader, target string) {
	t.Helper()

	upgradeReq := fmt.Sprintf("GET /ws HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n",
		target)
	_, err := conn.Write([]byte(upgradeReq))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	statusLine, err := br.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, statusLine, "101")
	for {
		line, err := br.ReadString('\n')
		require.NoError(t, err)
		if line == "\r\n" {
			break
		}
	}

	_, err = conn.Write([]byte("hello websocket"))
	require.NoError(t, err)

	buf := make([]byte, 4096)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err := br.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello websocket", string(buf[:n]))
}

func TestTunnel_CONNECT_WebSocket(t *testing.T) {
	target := startWebSocketEchoUpstream(t)

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	wsUpgradeAndEcho(t, conn, br, target)
}

func TestTunnel_SOCKS5_WebSocket(t *testing.T) {
	target := startWebSocketEchoUpstream(t)

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	targetHost, targetPortStr, err := net.SplitHostPort(target)
	require.NoError(t, err)

	// SOCKS5 auth negotiation: version 5, 1 method (no auth)
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)

	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)
	require.Equal(t, []byte{0x05, 0x00}, authResp)

	// SOCKS5 connect request: IPv4
	ip := net.ParseIP(targetHost).To4()
	require.NotNil(t, ip)

	var port uint16
	_, err = fmt.Sscanf(targetPortStr, "%d", &port)
	require.NoError(t, err)

	connectReq := []byte{0x05, 0x01, 0x00, 0x01} // ver, cmd=connect, rsv, atyp=IPv4
	connectReq = append(connectReq, ip...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	connectReq = append(connectReq, portBuf...)

	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), connectResp[0]) // version
	require.Equal(t, byte(0x00), connectResp[1]) // success

	wsUpgradeAndEcho(t, conn, bufio.NewReader(conn), target)
}

// TestServeOneHTTPConn_HijackWaitsForHandler pins the contract that lets
// hijacking handlers (WebSocket relays, CONNECT tunnels) survive their
// callers' deferred conn.Close(): serveOneHTTPConn must not return until a
// hijacking handler has finished with the connection. This covers the TLS
// MITM branch too, which cannot be exercised end-to-end because
// handleWebSocket verifies upstream certificates against system roots.
func TestServeOneHTTPConn_HijackWaitsForHandler(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	release := make(chan struct{})
	serveReturned := make(chan struct{})

	go func() {
		defer close(serveReturned)
		err := serveOneHTTPConn(serverConn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Background HTTP handler: report failures via t.Error.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("hijacking not supported")
				return
			}
			conn, rw, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			defer conn.Close()
			if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n\r\n"); err != nil {
				t.Errorf("write 101: %v", err)
				return
			}
			if err := rw.Flush(); err != nil {
				t.Errorf("flush 101: %v", err)
				return
			}
			<-release
		}))
		if err != nil {
			t.Errorf("serveOneHTTPConn: %v", err)
		}
	}()

	_, err := clientConn.Write([]byte("GET /ws HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)

	// Read the 101 status line so the hijack has definitely happened.
	br := bufio.NewReader(clientConn)
	statusLine, err := br.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, statusLine, "101")

	select {
	case <-serveReturned:
		t.Fatal("serveOneHTTPConn returned while the hijacking handler was still running")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-serveReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("serveOneHTTPConn did not return after the hijacking handler finished")
	}
}
