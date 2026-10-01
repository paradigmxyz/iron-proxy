package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// failingTransform stands in for a policy transform whose backend is down: it
// errors instead of returning a verdict.
type failingTransform struct{}

func (failingTransform) Name() string { return "failing-authz" }

func (failingTransform) TransformRequest(context.Context, *transform.TransformContext, *http.Request) (*transform.TransformResult, error) {
	return nil, errors.New("authz backend timeout")
}

func (failingTransform) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// A CONNECT whose transform errors is not a verdict on the request, so it must
// be 503 + Retry-After rather than 403, the audit line must agree with what the
// client was sent, and the body must not name the transform or its error.
func TestTunnel_CONNECT_TransformErrorIs503(t *testing.T) {
	pipeline := transform.NewPipeline([]transform.Transformer{failingTransform{}}, transform.BodyLimits{}, testLogger())
	audited := make(chan *transform.PipelineResult, 1)
	pipeline.SetAuditFunc(func(r *transform.PipelineResult) { audited <- r })
	p := New(Options{
		HTTPAddr:   "127.0.0.1:0",
		TunnelAddr: "127.0.0.1:0",
		Pipeline:   transform.NewPipelineHolder(pipeline),
		Logger:     testLogger(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleTunnel(conn)
		}
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "1", resp.Header.Get("Retry-After"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NotContains(t, string(body), "authz backend timeout")
	require.NotContains(t, string(body), "failing-authz")

	select {
	case r := <-audited:
		require.Equal(t, http.StatusServiceUnavailable, r.StatusCode)
		require.Error(t, r.Err)
	case <-time.After(2 * time.Second):
		t.Fatal("no audit entry for the CONNECT")
	}
}
