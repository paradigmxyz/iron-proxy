// Package hostmatch provides domain glob and literal-IP CIDR matching for
// host-based access control, shared by the allowlist and secrets transforms.
package hostmatch

import (
	"fmt"
	"net"
	"path"
	"strings"
	"unicode/utf8"
)

// Matcher checks whether a host matches a set of domain globs or, when the
// host is a literal IP address, a set of CIDR ranges.
type Matcher struct {
	domains []string
	cidrs   []*net.IPNet
}

// New creates a Matcher from domain globs and CIDR strings.
func New(domains []string, cidrs []string) (*Matcher, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parsing CIDR %q: %w", cidr, err)
		}
		nets = append(nets, ipNet)
	}

	return &Matcher{
		domains: domains,
		cidrs:   nets,
	}, nil
}

// Matches returns true if the host matches any domain glob, or — when the
// host is itself a literal IP — falls inside any configured CIDR range. The
// host should already have the port stripped. Hosts that are not in canonical
// form (see IsCanonicalHost) never match.
func (m *Matcher) Matches(host string) bool {
	if !IsCanonicalHost(host) {
		return false
	}
	for _, pattern := range m.domains {
		if MatchGlob(pattern, host) {
			return true
		}
	}

	if len(m.cidrs) > 0 {
		if ip := net.ParseIP(host); ip != nil {
			for _, cidr := range m.cidrs {
				if cidr.Contains(ip) {
					return true
				}
			}
		}
	}

	return false
}

// IsCanonicalHost reports whether host (port already stripped) is in the
// ASCII form the network stack dials. Non-ASCII names are rejected because
// policy would compare them differently than the transport's IDNA encoding,
// and "%" is rejected because an IPv6 zone identifier would let an IP literal
// carry an arbitrary domain-like suffix.
func IsCanonicalHost(host string) bool {
	for i := 0; i < len(host); i++ {
		if host[i] >= utf8.RuneSelf || host[i] == '%' {
			return false
		}
	}
	return true
}

// MatchGlob matches a domain against a glob pattern.
// "*" matches any host. "*.example.com" matches any subdomain depth and
// "example.com" itself. Matching is ASCII case-insensitive per RFC 4343;
// Unicode case folding is deliberately not applied (e.g. U+0130 must not
// fold to "i").
func MatchGlob(pattern, name string) bool {
	pattern = asciiLower(pattern)
	name = asciiLower(name)
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(name, suffix) || name == pattern[2:]
	}
	matched, _ := path.Match(pattern, name)
	return matched
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// StripPort removes the port from a host:port string. If there's no port,
// the host is returned. IPv6 brackets (e.g. [::1]) are stripped for clean
// IP parsing and domain matching.
func StripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(host, "[]")
}
