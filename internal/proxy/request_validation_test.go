package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// hostRejecter rejects any request whose Host (port stripped) is in deny.
type hostRejecter struct{ deny map[string]bool }

func (h *hostRejecter) Name() string { return "host_rejecter" }

func (h *hostRejecter) TransformRequest(_ context.Context, _ *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if h.deny[hostmatch.StripPort(req.Host)] {
		return &transform.TransformResult{Action: transform.ActionReject}, nil
	}
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (h *hostRejecter) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// startAuditedProxy starts a plain-HTTP proxy with the given transforms and
// returns its address plus an accessor for emitted audit records.
func startAuditedProxy(t *testing.T, transforms []transform.Transformer) (string, func() []transform.PipelineResult) {
	t.Helper()
	var mu sync.Mutex
	var records []transform.PipelineResult
	pipeline := transform.NewPipeline(transforms, transform.BodyLimits{}, testLogger())
	pipeline.SetAuditFunc(func(r *transform.PipelineResult) {
		mu.Lock()
		defer mu.Unlock()
		records = append(records, *r)
	})
	p := New(Options{
		HTTPAddr: "127.0.0.1:0",
		Pipeline: transform.NewPipelineHolder(pipeline),
		Logger:   testLogger(),
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.httpServer.Serve(ln) }()
	t.Cleanup(func() { _ = p.httpServer.Close() })

	return ln.Addr().String(), func() []transform.PipelineResult {
		mu.Lock()
		defer mu.Unlock()
		return append([]transform.PipelineResult(nil), records...)
	}
}

func TestHTTPProxy_RejectsAmbiguousRequests(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
	require.NoError(t, err)
	upstreamAddr := upstream.Listener.Addr().String()

	cases := []struct {
		name   string
		raw    string
		reason string
	}{
		{
			name:   "opaque request target",
			raw:    "GET http:http://" + upstreamAddr + "/get HTTP/1.1\r\nHost: " + upstreamAddr + "\r\n\r\n",
			reason: "unsupported_request_target",
		},
		{
			name:   "ipv6 zone in host",
			raw:    "GET / HTTP/1.1\r\nHost: [::ffff:127.0.0.1%x.allowed.example]:" + port + "\r\n\r\n",
			reason: "non_canonical_host",
		},
		{
			name:   "non-ascii host",
			raw:    "GET http://api.g%C4%B0thub.com/ HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
			reason: "non_canonical_host",
		},
		{
			name:   "dot segment with path parameter",
			raw:    "GET /get/..;/headers HTTP/1.1\r\nHost: " + upstreamAddr + "\r\n\r\n",
			reason: "dot_segments",
		},
		{
			name:   "dot segment with encoded backslash",
			raw:    "GET /get/..%5cheaders HTTP/1.1\r\nHost: " + upstreamAddr + "\r\n\r\n",
			reason: "dot_segments",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxyAddr, audits := startAuditedProxy(t, nil)
			conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			require.NoError(t, err)
			defer conn.Close()
			_, err = conn.Write([]byte(tc.raw))
			require.NoError(t, err)
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			require.Zero(t, upstreamHits.Load())

			require.Eventually(t, func() bool { return len(audits()) == 1 }, 2*time.Second, 10*time.Millisecond)
			rec := audits()[0]
			require.Equal(t, transform.ActionReject, rec.Action)
			require.Equal(t, http.StatusBadRequest, rec.StatusCode)
			require.Len(t, rec.RequestTransforms, 1)
			require.Equal(t, "request_validation", rec.RequestTransforms[0].Name)
			require.Equal(t, tc.reason, rec.RequestTransforms[0].Annotations["reason"])
		})
	}
}

func TestContainsDotSegments_ServerSpecificSeparators(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/get/..;/headers", true},
		{"/get/..;jsessionid=x/headers", true},
		{"/get/.;/headers", true},
		{`/get/..\headers`, true},
		{`\..\headers`, true},
		{"/get;v=1/headers", false},
		{"/get/a..b;c", false},
		{`/get/a\b`, false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			require.Equal(t, tc.want, containsDotSegments(tc.path))
		})
	}
}

// startRawUpstream accepts one connection and hands it to serve.
func startRawUpstream(t *testing.T, serve func(conn net.Conn, br *bufio.Reader)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed at test end
		}
		defer conn.Close()
		serve(conn, bufio.NewReader(conn))
	}()
	return ln.Addr().String()
}

func TestHTTPProxy_WebSocketRefusedUpgradeIsNotTunneled(t *testing.T) {
	extra := make(chan string, 1)
	upstreamAddr := startRawUpstream(t, func(conn net.Conn, br *bufio.Reader) {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = req.Body.Close() // GET without body
		// Refuse the upgrade but keep the connection open.
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 4096)
		n, _ := br.Read(buf) // timeout/EOF expected when nothing is relayed
		extra <- string(buf[:n])
	})

	proxyAddr, audits := startAuditedProxy(t, []transform.Transformer{
		&hostRejecter{deny: map[string]bool{"blocked.example": true}},
	})
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	br := bufio.NewReader(conn)

	_, err = fmt.Fprintf(conn, "GET /public HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", upstreamAddr)
	require.NoError(t, err)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "ok", string(body))

	// The next request on the same client connection must go through the
	// pipeline again rather than be relayed raw to the upstream.
	_, err = io.WriteString(conn, "POST /admin HTTP/1.1\r\nHost: blocked.example\r\nContent-Length: 0\r\n\r\n")
	require.NoError(t, err)
	resp, err = http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	require.Empty(t, <-extra, "upstream must not receive bytes after a refused upgrade")

	require.Eventually(t, func() bool { return len(audits()) == 2 }, 2*time.Second, 10*time.Millisecond)
	recs := audits()
	require.Equal(t, http.StatusOK, recs[0].StatusCode)
	require.Equal(t, transform.ActionReject, recs[1].Action)
	require.Equal(t, "blocked.example", recs[1].Host)
}

func TestHTTPProxy_WebSocketUsesOriginFormUpstream(t *testing.T) {
	gotRequest := make(chan string, 1)
	upstreamAddr := startRawUpstream(t, func(conn net.Conn, br *bufio.Reader) {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		var hostHeader string
		for {
			h, err := br.ReadString('\n')
			if err != nil || h == "\r\n" {
				break
			}
			if strings.HasPrefix(strings.ToLower(h), "host:") {
				hostHeader = strings.TrimSpace(h[len("host:"):])
			}
		}
		gotRequest <- strings.TrimSpace(line) + " | " + hostHeader
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	})

	proxyAddr, _ := startAuditedProxy(t, nil)
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	// Absolute-form target: the upstream must still see origin-form with the
	// policy-evaluated authority in Host.
	_, err = fmt.Fprintf(conn, "GET http://%s/ws?x=1 HTTP/1.1\r\nHost: ignored.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", upstreamAddr)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	require.Equal(t, "GET /ws?x=1 HTTP/1.1 | "+upstreamAddr, <-gotRequest)
}
