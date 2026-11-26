package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

func TestTunnelCredentialPropagatesToInnerTransforms(t *testing.T) {
	seen := make(chan *transform.TunnelInfo, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{&tunnelInfoTransform{seen: seen}})
	target := upstream.Listener.Addr().String()

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n", target, target)
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
		require.Equal(t, "Basic dXNlcjpwYXNz", info.Credential)
	case <-time.After(2 * time.Second):
		t.Fatal("inner transform did not receive tunnel info")
	}
}
