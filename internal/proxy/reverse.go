package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ReverseTLSConfig returns the TLS configuration of the reverse listener: the
// proxy's own certificate, with client certificates required and verified
// against the PEM certificates in clientCAFile.
func ReverseTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading reverse listener certificate: %w", err)
	}
	pem, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("reading reverse listener client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("reverse listener client CA %s holds no PEM certificates", clientCAFile)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// serveReverse serves the reverse listener until it is shut down.
func (p *Proxy) serveReverse() error {
	ln, err := net.Listen("tcp", p.reverseServer.Addr)
	if err != nil {
		return fmt.Errorf("reverse listen: %w", err)
	}
	p.logger.Info("reverse proxy starting", slog.String("addr", ln.Addr().String()))
	return fmt.Errorf("reverse: %w", p.reverseServer.Serve(tls.NewListener(ln, p.reverseServer.TLSConfig)))
}

// handleReverse serves a request of the reverse listener, whose TLS layer has
// verified the client's certificate. The first path segment names the
// upstream host: /<host>/<path> goes to https://<host>/<path> through the
// transform pipeline.
func (p *Proxy) handleReverse(w http.ResponseWriter, r *http.Request) {
	// A request-target such as //host/path parses as an authority; only an
	// origin-form path names the upstream.
	host, rest, ok := reverseTarget(r.URL.EscapedPath())
	if !ok || r.URL.Host != "" || r.URL.Opaque != "" {
		http.Error(w, "the path must start with the upstream host: /<host>/<path>", http.StatusBadRequest)
		return
	}
	target, err := url.ParseRequestURI(rest)
	if err != nil {
		http.Error(w, "invalid upstream path", http.StatusBadRequest)
		return
	}
	if containsDotSegments(target.Path) {
		http.Error(w, "path contains dot segments", http.StatusBadRequest)
		return
	}
	r.Host = host
	r.URL.Host = host
	r.URL.Path = target.Path
	r.URL.RawPath = target.RawPath
	// Cloudflare adds CF-Worker and other Cf-* headers to every Worker
	// subrequest. They describe the hop to iron-proxy, not the client's
	// request, and some upstreams refuse requests that carry them.
	for name := range r.Header {
		if strings.HasPrefix(name, "Cf-") || name == "Cdn-Loop" {
			r.Header.Del(name)
		}
	}
	p.proxyRequest(w, r, nil, "https", host, "")
}

var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

// reverseTarget splits an escaped request path into the upstream host named
// by its first segment and the rest of the path.
func reverseTarget(escapedPath string) (host, rest string, ok bool) {
	trimmed, found := strings.CutPrefix(escapedPath, "/")
	if !found {
		return "", "", false
	}
	host, rest, _ = strings.Cut(trimmed, "/")
	if !validUpstreamHost(host) {
		return "", "", false
	}
	return host, "/" + rest, true
}

// validUpstreamHost reports whether host is a hostname or IP address, with an
// optional port.
func validUpstreamHost(host string) bool {
	name := host
	if strings.Contains(host, ":") {
		h, port, err := net.SplitHostPort(host)
		if err != nil {
			return false
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
		name = h
	}
	return net.ParseIP(name) != nil || hostnamePattern.MatchString(name)
}
