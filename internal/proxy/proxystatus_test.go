package proxy

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/proxystatus"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
)

// buildProxyStatusProxy stands up an HTTP proxy with the given allowlist, deny
// CIDRs and Proxy-Status identity, and returns its address.
func buildProxyStatusProxy(t *testing.T, allowed []string, denyCIDRs []string, statusName string) string {
	return buildProxyStatusProxyV(t, allowed, denyCIDRs, statusName, false)
}

func buildProxyStatusProxyV(t *testing.T, allowed []string, denyCIDRs []string, statusName string, verbose bool) string {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	al, err := allowlist.New(allowed, nil)
	require.NoError(t, err)
	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)

	guard, err := dnsguard.New(denyCIDRs)
	require.NoError(t, err)

	p := New(Options{
		HTTPAddr:           "127.0.0.1:0",
		Pipeline:           transform.NewPipelineHolder(pipeline),
		Guard:              guard,
		Logger:             logger,
		ProxyStatusName:    statusName,
		ProxyStatusVerbose: verbose,
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.httpServer.Serve(ln) }()
	t.Cleanup(func() { _ = p.httpServer.Close() })

	return ln.Addr().String()
}

func proxyClient(addr string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
		},
		Timeout: 5 * time.Second,
	}
}

// By default a deny-CIDR block must be INDISTINGUISHABLE from any other
// unreachable destination. A client that can only reach the network through
// this proxy would otherwise use the error type as a probe oracle — learning
// which internal ranges are filtered, one CONNECT at a time. RFC 9209 S4.
func TestProxyStatus_DenyCIDRIsNotDisclosedByDefault(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr := buildProxyStatusProxy(t, []string{"*"}, []string{"127.0.0.0/8"}, "iron-test")

	resp, err := proxyClient(proxyAddr).Get(upstream.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	got := resp.Header.Get(proxystatus.HeaderName)
	require.Contains(t, got, "iron-test")
	require.Contains(t, got, "error="+proxystatus.ErrDestinationUnavailable)

	require.NotContains(t, got, proxystatus.ErrDestinationIPProhibited,
		"naming the policy tells the client this range is filtered")
	require.NotContains(t, got, "details=",
		"details echoed the blocked address, which is the address itself leaking back")
	for _, leak := range []string{"127.0.0", "deny", "CIDR", "cidr", "next-hop"} {
		require.NotContains(t, got, leak)
	}
	// The whole default payload: identity + coarse class, nothing else.
	require.Equal(t, "iron-test; error=destination_unavailable", got)
}

// Operators running a proxy for trusted clients can still get the precise
// cause — the disclosure is a choice, not a limitation.
func TestProxyStatus_VerboseRevealsProhibitedForTrustedClients(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr := buildProxyStatusProxyV(t, []string{"*"}, []string{"127.0.0.0/8"}, "iron-test", true)

	resp, err := proxyClient(proxyAddr).Get(upstream.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Contains(t, resp.Header.Get(proxystatus.HeaderName),
		"error="+proxystatus.ErrDestinationIPProhibited)
}

// An allowlist rejection is the proxy refusing on the request's merits, which
// is http_request_denied — distinct from the origin returning 403 itself.
func TestProxyStatus_AllowlistRejectIsReportedAsDenied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Allow only a host the request will not use, so the allowlist rejects.
	proxyAddr := buildProxyStatusProxy(t, []string{"allowed.example.com"}, nil, "iron-test")

	resp, err := proxyClient(proxyAddr).Get(upstream.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.GreaterOrEqual(t, resp.StatusCode, 400)
	require.Less(t, resp.StatusCode, 500)

	got := resp.Header.Get(proxystatus.HeaderName)
	require.Contains(t, got, "iron-test")
	require.Contains(t, got, "error="+proxystatus.ErrHTTPRequestDenied)
}

// The feature is opt-in: with no configured identity there is no meaningful
// RFC 9209 member to emit, so the header must be absent entirely rather than
// present-but-anonymous.
func TestProxyStatus_DisabledWithoutName(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr := buildProxyStatusProxy(t, []string{"*"}, []string{"127.0.0.0/8"}, "")

	resp, err := proxyClient(proxyAddr).Get(upstream.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	require.Empty(t, resp.Header.Get(proxystatus.HeaderName))
}

// A successfully proxied response is the origin's, not the proxy's. Stamping
// an error onto it would misattribute the origin's own status.
func TestProxyStatus_AbsentOnSuccessfulProxying(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr := buildProxyStatusProxy(t, []string{"*"}, nil, "iron-test")

	resp, err := proxyClient(proxyAddr).Get(upstream.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Empty(t, resp.Header.Get(proxystatus.HeaderName))
}

// A CONNECT refused by a transform is a proxy-generated response too.
func TestProxyStatus_CONNECTRejectIsAnnotated(t *testing.T) {
	al, err := allowlist.New([]string{"allowed.example.com"}, nil)
	require.NoError(t, err)
	p, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{al})
	p.proxyStatusName = "iron-test"

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "CONNECT blocked.example.com:443 HTTP/1.1\r\nHost: blocked.example.com:443\r\n\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.Equal(t, "iron-test; error="+proxystatus.ErrHTTPRequestDenied, resp.Header.Get(proxystatus.HeaderName))
}
