package proxystatus

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestItemString(t *testing.T) {
	cases := []struct {
		name string
		item Item
		want string
	}{
		{"proxy only", Item{Proxy: "iron"}, "iron"},
		{"error as token", Item{Proxy: "iron", Error: ErrHTTPRequestDenied}, "iron; error=http_request_denied"},
		{"details quoted", Item{Proxy: "iron", Error: ErrDestinationIPProhibited, Details: "169.254.169.254 denied"},
			`iron; error=destination_ip_prohibited; details="169.254.169.254 denied"`},
		{"next-hop", Item{Proxy: "iron", NextHop: "example.com:443"}, "iron; next-hop=example.com:443"},
		{"dotted name stays a token", Item{Proxy: "egress.internal.example.com"}, "egress.internal.example.com"},
		{"leading digit is quoted", Item{Proxy: "4proxy"}, `"4proxy"`},
		{"space is quoted", Item{Proxy: "my proxy"}, `"my proxy"`},
		{"details escapes quotes and backslashes", Item{Proxy: "iron", Details: `he said "hi" \ bye`},
			`iron; details="he said \"hi\" \\ bye"`},
		// A raw CR/LF in details would split the header and allow injection.
		{"details drops non-printable bytes", Item{Proxy: "iron", Details: "before\r\nX-Injected: yes\tafter\x00"},
			`iron; details="beforeX-Injected: yesafter"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.item.String())
		})
	}
}

func TestAppend(t *testing.T) {
	t.Run("sets header", func(t *testing.T) {
		h := http.Header{}
		Append(h, Item{Proxy: "iron", Error: ErrHTTPRequestDenied})
		require.Equal(t, "iron; error=http_request_denied", h.Get(HeaderName))
	})
	t.Run("preserves an upstream proxy's member", func(t *testing.T) {
		h := http.Header{HeaderName: {"upstream; error=connection_refused"}}
		Append(h, Item{Proxy: "iron", Error: ErrHTTPRequestDenied})
		require.Equal(t, "upstream; error=connection_refused, iron; error=http_request_denied", h.Get(HeaderName))
	})
	t.Run("blank proxy name is a no-op", func(t *testing.T) {
		for _, name := range []string{"", "   "} {
			h := http.Header{}
			Append(h, Item{Proxy: name, Error: ErrHTTPRequestDenied})
			require.Empty(t, h.Get(HeaderName))
		}
	})
	t.Run("nil header does not panic", func(t *testing.T) {
		Append(nil, Item{Proxy: "iron"})
	})
}
