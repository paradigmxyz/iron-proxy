package dnsguard

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNew_RejectsBareIPs(t *testing.T) {
	tests := []string{
		"1.2.3.4",
		"169.254.169.254",
		"::1",
		"fd00:ec2::254",
	}
	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			_, err := New([]string{in})
			require.Error(t, err)
			require.Contains(t, err.Error(), "must be CIDR notation")
		})
	}
}

func TestNew_RejectsMalformed(t *testing.T) {
	tests := []string{
		"not-an-ip/24",
		"999.999.999.999/32",
		"10.0.0.0/99",
		"  ",
	}
	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			_, err := New([]string{in})
			require.Error(t, err)
		})
	}
}

func TestNew_AcceptsValid(t *testing.T) {
	g, err := New([]string{
		"169.254.169.254/32",
		"127.0.0.0/8",
		"::1/128",
		"fd00:ec2::254/128",
		"10.0.0.0/8",
	})
	require.NoError(t, err)
	require.NotNil(t, g)
}

func TestDefaultDenyCIDRsBlockMetadataAddresses(t *testing.T) {
	guard, err := New(DefaultDenyCIDRs)
	require.NoError(t, err)

	for _, address := range []string{
		"169.254.169.254",
		"fd00:ec2::254",
		"fd20:ce::254",
	} {
		t.Run(address, func(t *testing.T) {
			require.True(t, guard.IsDenied(netip.MustParseAddr(address)))
		})
	}
}

func TestContainsMetadataAddress(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		contains bool
	}{
		{name: "IPv4 metadata", prefix: "169.254.169.254/32", contains: true},
		{name: "AWS IPv6 metadata", prefix: "fd00::/8", contains: true},
		{name: "GCP IPv6 metadata", prefix: "fd20:ce::/64", contains: true},
		{name: "unrelated private IPv4", prefix: "10.0.0.0/8", contains: false},
		{name: "unrelated unique local IPv6", prefix: "fd12:3456::/48", contains: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.contains, ContainsMetadataAddress(netip.MustParsePrefix(tc.prefix)))
		})
	}
}

func TestNew_NilAndEmpty(t *testing.T) {
	g, err := New(nil)
	require.NoError(t, err)
	require.False(t, g.IsDenied(netip.MustParseAddr("169.254.169.254")))

	g, err = New([]string{})
	require.NoError(t, err)
	require.False(t, g.IsDenied(netip.MustParseAddr("127.0.0.1")))
}

func TestIsDenied(t *testing.T) {
	g, err := New([]string{
		"169.254.169.254/32",
		"127.0.0.0/8",
		"::1/128",
	})
	require.NoError(t, err)

	denied := []string{
		"169.254.169.254",
		"127.0.0.1",
		"127.255.255.254",
		"::1",
	}
	for _, ip := range denied {
		t.Run("denied/"+ip, func(t *testing.T) {
			require.True(t, g.IsDenied(netip.MustParseAddr(ip)))
		})
	}

	allowed := []string{
		"169.254.169.253",
		"169.254.170.0",
		"128.0.0.0",
		"8.8.8.8",
		"::2",
		"2001:db8::1",
	}
	for _, ip := range allowed {
		t.Run("allowed/"+ip, func(t *testing.T) {
			require.False(t, g.IsDenied(netip.MustParseAddr(ip)))
		})
	}
}

func TestIsDenied_4in6Mapped(t *testing.T) {
	g, err := New([]string{"127.0.0.0/8"})
	require.NoError(t, err)

	mapped := netip.MustParseAddr("::ffff:127.0.0.1")
	require.True(t, g.IsDenied(mapped))
}

func TestDialControl_DenyAndAllow(t *testing.T) {
	g, err := New([]string{"127.0.0.0/8", "169.254.169.254/32"})
	require.NoError(t, err)

	t.Run("denied ipv4", func(t *testing.T) {
		err := g.DialControl("tcp", "127.0.0.1:443", nil)
		require.Error(t, err)
		require.True(t, IsDenyError(err))
	})

	t.Run("denied imds", func(t *testing.T) {
		err := g.DialControl("tcp", "169.254.169.254:80", nil)
		require.Error(t, err)
		var de *DenyError
		require.ErrorAs(t, err, &de)
		require.Equal(t, "169.254.169.254", de.Address)
	})

	t.Run("allowed ipv4", func(t *testing.T) {
		require.NoError(t, g.DialControl("tcp", "8.8.8.8:443", nil))
	})

	t.Run("4-in-6 mapped denied", func(t *testing.T) {
		err := g.DialControl("tcp", "[::ffff:127.0.0.1]:443", nil)
		require.Error(t, err)
		require.True(t, IsDenyError(err))
	})

	t.Run("malformed address allowed", func(t *testing.T) {
		// Not our job to reject malformed addresses — Go's connect will fail.
		require.NoError(t, g.DialControl("tcp", "not-an-address", nil))
	})
}

func TestDialControl_EmptyGuardNoop(t *testing.T) {
	g, err := New(nil)
	require.NoError(t, err)
	require.NoError(t, g.DialControl("tcp", "127.0.0.1:443", nil))
}

func TestDialContextRejectsDeniedAddressAfterHostnameResolution(t *testing.T) {
	g, err := New([]string{"127.0.0.0/8", "::1/128"})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	connection, err := g.DialContext(
		ctx,
		&net.Dialer{Timeout: time.Second},
		"tcp",
		"localhost:443",
	)
	if connection != nil {
		_ = connection.Close()
	}
	require.Error(t, err)
	require.True(t, IsDenyError(err), "resolved loopback must fail at the dial guard")
}

func TestDialControl_NilGuardNoop(t *testing.T) {
	var g *Guard
	require.NoError(t, g.DialControl("tcp", "127.0.0.1:443", nil))
}

func TestPrivateException_IsExactHostnameAndAddress(t *testing.T) {
	g, err := NewWithExceptions(
		[]string{"10.0.0.0/8", "169.254.0.0/16"},
		map[string][]string{"managed-rpc": {"10.23.4.5/32"}},
	)
	require.NoError(t, err)

	cases := []struct {
		name, host, address string
		allow               bool
	}{
		{"exact match", "managed-rpc", "10.23.4.5:8899", true},
		{"canonical hostname", "MANAGED-RPC.", "10.23.4.5:8899", true},
		{"wrong address", "managed-rpc", "10.23.4.6:8899", false},
		{"wrong host", "other-rpc", "10.23.4.5:8899", false},
		{"literal IP", "10.23.4.5", "10.23.4.5:8899", false},
		{"metadata address", "managed-rpc", "169.254.169.254:80", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.allow, g.dialControlForHost(tc.host, tc.address) == nil)
		})
	}
	// The compatibility hook has no original hostname and therefore never
	// applies private exceptions.
	require.Error(t, g.DialControl("tcp", "10.23.4.5:8899", nil))
}

func TestPrivateException_RejectsUnsafeConfiguration(t *testing.T) {
	cases := []struct{ name, host, prefix string }{
		{"empty host", "", "10.0.0.2/32"},
		{"wildcard", "*.example", "10.0.0.2/32"},
		{"literal IP", "10.0.0.1", "10.0.0.2/32"},
		{"port in host", "rpc:8899", "10.0.0.2/32"},
		{"invalid host", "-rpc", "10.0.0.2/32"},
		{"missing prefix", "managed-rpc", "10.0.0.2"},
		{"broad IPv4 prefix", "managed-rpc", "10.0.0.0/8"},
		{"broad IPv6 prefix", "managed-rpc", "2001:db8::/64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewWithExceptions(nil, map[string][]string{tc.host: {tc.prefix}})
			require.Error(t, err)
		})
	}
}
