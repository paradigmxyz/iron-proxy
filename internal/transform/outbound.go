package transform

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

// DialFunc opens a connection on behalf of a transform or secret source's own
// outbound request.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

var (
	outboundMu   sync.RWMutex
	outboundDial DialFunc

	defaultClientMu             sync.Mutex
	savedDefaultClientTransport http.RoundTripper
	defaultClientTransportSaved bool
)

// SetOutboundDialer installs a process-wide dialer for outbound requests made
// by transforms and secret sources (OAuth token endpoints, GCP token
// exchanges, AWS SDK calls, Vault, the judge LLM providers, the gRPC transform,
// and the 1Password Connect SDK). Passing nil restores the previous behavior.
//
// http.DefaultClient is redirected because the 1Password Connect SDK hard-codes
// it. Callers that build their own transports use OutboundDialer.
func SetOutboundDialer(dial DialFunc) {
	outboundMu.Lock()
	outboundDial = dial
	outboundMu.Unlock()

	defaultClientMu.Lock()
	defer defaultClientMu.Unlock()
	if dial == nil {
		if defaultClientTransportSaved {
			http.DefaultClient.Transport = savedDefaultClientTransport
			savedDefaultClientTransport = nil
			defaultClientTransportSaved = false
		}
		return
	}
	if !defaultClientTransportSaved {
		savedDefaultClientTransport = http.DefaultClient.Transport
		defaultClientTransportSaved = true
	}
	http.DefaultClient.Transport = NewOutboundTransport()
}

// OutboundDialer returns the installed dialer, or nil when none is installed.
func OutboundDialer() DialFunc {
	outboundMu.RLock()
	defer outboundMu.RUnlock()
	return outboundDial
}

// NewOutboundTransport returns an HTTP transport whose dials use the installed
// outbound dialer. Without an installed dialer it behaves like the default
// transport.
func NewOutboundTransport() *http.Transport {
	var tr *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = base.Clone()
	} else {
		tr = &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		}
	}
	tr.DialContext = DialOutbound
	// With a guard installed, dial destinations directly: through an env
	// proxy the guard would only see the proxy's address.
	if OutboundDialer() != nil {
		tr.Proxy = nil
	}
	return tr
}

// DialOutbound dials through the installed outbound dialer. The installed
// dialer is looked up per call, so it also applies to clients constructed
// before installation. Without an installed dialer it uses the same default
// dialer as NewOutboundTransport.
func DialOutbound(ctx context.Context, network, addr string) (net.Conn, error) {
	if dial := OutboundDialer(); dial != nil {
		return dial(ctx, network, addr)
	}
	fallback := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return fallback.DialContext(ctx, network, addr)
}

// NewOutboundClient returns an HTTP client whose dials use the installed
// outbound dialer. Without an installed dialer it behaves like the default
// client.
func NewOutboundClient() *http.Client {
	return &http.Client{Transport: NewOutboundTransport()}
}
