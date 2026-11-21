package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// freeAddr returns a loopback address nothing listens on (now).
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// startProxyWithTunnels runs ListenAndServe with a tunnel on tunnelAddr and
// on each of extra, and waits until every tunnel address accepts.
func startProxyWithTunnels(t *testing.T, holder *transform.PipelineHolder, tunnelAddr string, extra []string) (*Proxy, chan error) {
	t.Helper()
	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)
	p := New(Options{
		HTTPAddr:         "127.0.0.1:0",
		HTTPSAddr:        "127.0.0.1:0",
		TunnelAddr:       tunnelAddr,
		ExtraTunnelAddrs: extra,
		CertCache:        cache,
		Pipeline:         holder,
		Logger:           testLogger(),
	})
	errc := make(chan error, 1)
	go func() { errc <- p.ListenAndServe() }()
	for _, addr := range append([]string{tunnelAddr}, extra...) {
		require.Eventually(t, func() bool {
			c, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				return false
			}
			_ = c.Close()
			return true
		}, 5*time.Second, 10*time.Millisecond, "tunnel %s never accepted", addr)
	}
	return p, errc
}

// connectVia sends CONNECT target through the tunnel at addr and returns the
// status; on 200 it also sends GET / through the tunnel and returns its body.
func connectVia(t *testing.T, addr, target string) (int, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, ""
	}
	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)
	resp2, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp2.Body.Close()
	body, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func TestTunnel_ExtraAddrsServeTheSamePipeline(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "upstream")
	}))
	defer upstream.Close()
	target := upstream.Listener.Addr().String()

	holder := transform.NewPipelineHolder(transform.NewPipeline(nil, transform.BodyLimits{}, testLogger()))
	primary, extra1, extra2 := freeAddr(t), freeAddr(t), freeAddr(t)
	p, errc := startProxyWithTunnels(t, holder, primary, []string{extra1, extra2})

	for _, addr := range []string{primary, extra1, extra2} {
		status, body := connectVia(t, addr, target)
		require.Equal(t, http.StatusOK, status, addr)
		require.Equal(t, "upstream", body, addr)
	}

	// A reload (a new pipeline in the holder) reaches every address.
	holder.Store(transform.NewPipeline([]transform.Transformer{&rejectTransform{}}, transform.BodyLimits{}, testLogger()))
	for _, addr := range []string{primary, extra1, extra2} {
		status, _ := connectVia(t, addr, target)
		require.Equal(t, http.StatusForbidden, status, addr)
	}

	// Shutdown closes every address.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(ctx))
	for _, addr := range []string{primary, extra1, extra2} {
		require.Eventually(t, func() bool {
			c, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				return true
			}
			_ = c.Close()
			return false
		}, 5*time.Second, 10*time.Millisecond, "tunnel %s still accepts after Shutdown", addr)
	}
	select {
	case err := <-errc:
		// ListenAndServe always returns an error; after Shutdown it is the
		// first server reporting that it stopped.
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe did not return after Shutdown")
	}
}

func TestTunnel_ExtraAddrBindFailureFailsListenAndServe(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer taken.Close()

	holder := transform.NewPipelineHolder(transform.NewPipeline(nil, transform.BodyLimits{}, testLogger()))
	p := New(Options{
		HTTPAddr:         "127.0.0.1:0",
		HTTPSAddr:        "127.0.0.1:0",
		TunnelAddr:       freeAddr(t),
		ExtraTunnelAddrs: []string{taken.Addr().String()},
		CertCache:        nil,
		Pipeline:         holder,
		Logger:           testLogger(),
	})
	errc := make(chan error, 1)
	go func() { errc <- p.ListenAndServe() }()
	select {
	case err := <-errc:
		require.ErrorContains(t, err, "tunnel listen "+taken.Addr().String())
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe did not fail on a taken extra tunnel address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(ctx))
}
