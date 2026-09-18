package hostmatch

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "FOO.EXAMPLE.COM", true},
		{"*.EXAMPLE.COM", "foo.example.com", true},
		{"*.example.com", "bar.baz.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "EXAMPLE.COM", true},
		{"*.example.com", "notexample.com", false},
		{"exact.example.com", "exact.example.com", true},
		{"exact.example.com", "EXACT.EXAMPLE.COM", true},
		{"exact.example.com", "other.example.com", false},
		{"*", "anything.example.com", true},
		{"*", "1.2.3.4", true},
		{"*", "", true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.pattern, tt.name), func(t *testing.T) {
			require.Equal(t, tt.want, MatchGlob(tt.pattern, tt.name))
		})
	}
}

func TestStripPort(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:8080", "::1"},
		{"[::1]", "::1"},
		{"127.0.0.1:9090", "127.0.0.1"},
		{"127.0.0.1", "127.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			require.Equal(t, tt.want, StripPort(tt.host))
		})
	}
}
