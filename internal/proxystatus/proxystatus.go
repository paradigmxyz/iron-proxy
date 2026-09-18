// Package proxystatus serializes the Proxy-Status response header defined by
// RFC 9209, which lets an intermediary say that it generated a response and
// why. The field is an RFC 8941 Structured Fields list; each member names one
// proxy and carries parameters describing what it did:
//
//	Proxy-Status: egress; error=destination_ip_prohibited; details="10.0.0.1 denied"
package proxystatus

import (
	"net/http"
	"strings"
)

// HeaderName is the field name (RFC 9209, Section 2).
const HeaderName = "Proxy-Status"

// Error types from the IANA "HTTP Proxy-Status Error Types" registry
// (RFC 9209, Section 2.3) that a forward proxy emits.
const (
	ErrDNSTimeout              = "dns_timeout"
	ErrDNSError                = "dns_error"
	ErrDestinationUnavailable  = "destination_unavailable"
	ErrDestinationIPProhibited = "destination_ip_prohibited"
	ErrConnectionRefused       = "connection_refused"
	ErrConnectionTerminated    = "connection_terminated"
	ErrConnectionTimeout       = "connection_timeout"
	ErrTLSCertificateError     = "tls_certificate_error"
	ErrHTTPRequestDenied       = "http_request_denied"
	ErrProxyInternalError      = "proxy_internal_error"
)

// Item is one member of the Proxy-Status list. Only Proxy is required;
// zero-valued parameters are omitted.
type Item struct {
	Proxy   string // the intermediary's name
	Error   string // an error type, normally one of the Err* constants
	Details string // free-form context; RFC 9209 warns this can leak internals
	NextHop string // the upstream this item concerns
}

// String serializes the item as a single list member. Proxy and Error are
// emitted as sf-tokens when the grammar allows and as sf-strings otherwise, so
// any operator-chosen value is safe; Details is always an sf-string.
func (it Item) String() string {
	var b strings.Builder
	b.WriteString(encodeBareItem(it.Proxy))
	if it.Error != "" {
		b.WriteString("; error=")
		b.WriteString(encodeBareItem(it.Error))
	}
	if it.NextHop != "" {
		b.WriteString("; next-hop=")
		b.WriteString(encodeBareItem(it.NextHop))
	}
	if it.Details != "" {
		b.WriteString("; details=")
		b.WriteString(encodeString(it.Details))
	}
	return b.String()
}

// Append adds item to h's Proxy-Status field, after any member an upstream
// proxy already contributed. A blank item.Proxy is a no-op: RFC 9209 gives no
// meaning to an unidentified member.
func Append(h http.Header, item Item) {
	if h == nil || strings.TrimSpace(item.Proxy) == "" {
		return
	}
	encoded := item.String()
	if existing := h.Get(HeaderName); existing != "" {
		h.Set(HeaderName, existing+", "+encoded)
		return
	}
	h.Set(HeaderName, encoded)
}

func encodeBareItem(s string) string {
	if isToken(s) {
		return s
	}
	return encodeString(s)
}

// isToken reports whether s is an sf-token (RFC 8941, Section 3.3.4): an
// initial ALPHA or "*", then tchar / ":" / "/".
func isToken(s string) bool {
	if s == "" {
		return false
	}
	if c := s[0]; !isAlpha(c) && c != '*' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTokenChar(s[i]) {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isTokenChar(c byte) bool {
	if isAlpha(c) || (c >= '0' && c <= '9') {
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~', ':', '/':
		return true
	}
	return false
}

// encodeString renders s as an sf-string (RFC 8941, Section 3.3.3). The
// grammar admits only printable ASCII, so other bytes are dropped rather than
// emitted raw into a header.
func encodeString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' || c == '"':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c >= 0x20 && c <= 0x7E:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
