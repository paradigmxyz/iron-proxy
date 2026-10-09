// Package dnsguard rejects upstream connections to denied IP ranges at dial
// time. Enforcement runs in net.Dialer.Control after DNS resolution, so a
// hostname that resolves to a denied IP — even via DNS rebinding — is caught
// before the TCP connect.
package dnsguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

var metadataAddresses = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("fd20:ce::254"),
}

// DefaultDenyCIDRs is the secure-default list applied when the operator has
// not configured upstream_deny_cidrs. It blocks cloud instance metadata
// endpoints and loopback. RFC1918 is intentionally excluded — many legitimate
// iron-proxy deployments target private corporate networks.
var DefaultDenyCIDRs = defaultDenyCIDRs()

func defaultDenyCIDRs() []string {
	cidrs := make([]string, 0, len(metadataAddresses)+2)
	for _, address := range metadataAddresses {
		cidrs = append(cidrs, netip.PrefixFrom(address, address.BitLen()).String())
	}
	return append(cidrs, "127.0.0.0/8", "::1/128")
}

// ContainsMetadataAddress reports whether prefix contains a known cloud
// instance metadata address.
func ContainsMetadataAddress(prefix netip.Prefix) bool {
	for _, address := range metadataAddresses {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// DenyError reports a connection refused because the resolved address falls
// inside a denied CIDR.
type DenyError struct {
	Address string
	Prefix  netip.Prefix
}

func (e *DenyError) Error() string {
	return fmt.Sprintf("denied by upstream_deny_cidrs: %s in %s", e.Address, e.Prefix)
}

// IsDenyError reports whether err (or any wrapped error) is a *DenyError.
func IsDenyError(err error) bool {
	var de *DenyError
	return errors.As(err, &de)
}

// Guard holds the compiled deny prefixes and exposes hooks for the dialer.
// The zero value is a valid empty guard whose DialControl is a no-op.
type Guard struct {
	prefixes   []netip.Prefix
	exceptions map[string][]netip.Prefix
}

// New compiles a Guard from CIDR strings. CIDR notation is required: bare IPs
// like "1.2.3.4" are rejected, forcing operators to be explicit about scope.
// A nil or empty list yields an empty guard whose checks always pass.
func New(cidrs []string) (*Guard, error) {
	return NewWithExceptions(cidrs, nil)
}

// NewWithExceptions compiles a Guard with hostname-scoped exceptions. An
// exception permits an otherwise denied resolved IP only when the original
// dial target is the exact configured hostname and the IP is inside one of
// that hostname's prefixes. IP-literal targets can never use an exception.
func NewWithExceptions(cidrs []string, exceptions map[string][]string) (*Guard, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, raw := range cidrs {
		p, err := parsePrefix(raw)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, p)
	}
	compiledExceptions := make(map[string][]netip.Prefix, len(exceptions))
	for rawHost, rawPrefixes := range exceptions {
		host, err := canonicalExceptionHost(rawHost)
		if err != nil {
			return nil, err
		}
		for _, raw := range rawPrefixes {
			prefix, err := parsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("private exception %q: %w", rawHost, err)
			}
			if prefix.Bits() != prefix.Addr().BitLen() {
				return nil, fmt.Errorf(
					"private exception %q: %q must identify exactly one address (/32 or /128)",
					rawHost, raw,
				)
			}
			compiledExceptions[host] = append(compiledExceptions[host], prefix)
		}
	}
	return &Guard{prefixes: prefixes, exceptions: compiledExceptions}, nil
}

func canonicalExceptionHost(raw string) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if host == "" || strings.ContainsAny(host, ":/@*[]") {
		return "", fmt.Errorf("invalid private exception hostname %q", raw)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", fmt.Errorf("private exception hostname %q must not be an IP literal", raw)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid private exception hostname %q", raw)
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '_' {
				return "", fmt.Errorf("invalid private exception hostname %q", raw)
			}
		}
	}
	return host, nil
}

// ValidateCIDRs reports whether every entry in cidrs is a valid CIDR string
// in the form Guard expects (CIDR notation required; bare IPs rejected).
// Use this when only validation is needed — e.g. config validation that runs
// before a Guard is built.
func ValidateCIDRs(cidrs []string) error {
	for _, raw := range cidrs {
		if _, err := parsePrefix(raw); err != nil {
			return err
		}
	}
	return nil
}

// ValidateExceptions reports whether all private exception hostnames and
// prefixes are valid without constructing a Guard.
func ValidateExceptions(exceptions map[string][]string) error {
	_, err := NewWithExceptions(nil, exceptions)
	return err
}

func parsePrefix(raw string) (netip.Prefix, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("empty CIDR entry")
	}
	if !strings.Contains(s, "/") {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: must be CIDR notation, e.g. 1.2.3.4/32 or ::1/128", raw)
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", raw, err)
	}
	return p.Masked(), nil
}

// IsDenied reports whether ip falls inside any configured deny prefix.
func (g *Guard) IsDenied(ip netip.Addr) bool {
	if g == nil || len(g.prefixes) == 0 {
		return false
	}
	ip = ip.Unmap()
	for _, p := range g.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// DialControl is the net.Dialer.Control hook. Go invokes it after DNS
// resolution with the literal "host:port" about to be connected to; host is
// already an IP at this point, so name-based dials and IP-literal dials
// (e.g. SOCKS5 IPv4 atyp) are both covered. Returning an error aborts the
// connect.
func (g *Guard) DialControl(_ string, address string, _ syscall.RawConn) error {
	return g.dialControlForHost("", address)
}

// DialContext applies the guard while retaining the original hostname. A
// net.Dialer Control hook sees only the post-resolution IP, so the target name
// has to be captured per dial for destination-scoped exceptions to be safe.
func (g *Guard) DialContext(ctx context.Context, dialer *net.Dialer, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	copy := *dialer
	copy.Control = func(network, resolved string, raw syscall.RawConn) error {
		return g.dialControlForHost(host, resolved)
	}
	return copy.DialContext(ctx, network, address)
}

func (g *Guard) dialControlForHost(originalHost, address string) error {
	if g == nil || len(g.prefixes) == 0 {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	for _, p := range g.prefixes {
		if p.Contains(addr) {
			if g.isExcepted(originalHost, addr) {
				return nil
			}
			return &DenyError{Address: host, Prefix: p}
		}
	}
	return nil
}

func (g *Guard) isExcepted(originalHost string, address netip.Addr) bool {
	if g == nil || originalHost == "" {
		return false
	}
	if _, err := netip.ParseAddr(strings.Trim(originalHost, "[]")); err == nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(originalHost), ".")
	for _, prefix := range g.exceptions[host] {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
