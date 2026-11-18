package dnsguard

import (
	"net/netip"
	"testing"

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

	t.Run("malformed address refused", func(t *testing.T) {
		err := g.DialControl("tcp", "not-an-address", nil)
		require.Error(t, err)
		require.False(t, IsDenyError(err))
	})
}

func TestDialControl_Zones(t *testing.T) {
	g, err := New([]string{"127.0.0.0/8", "::1/128"})
	require.NoError(t, err)

	cases := []struct {
		name    string
		address string
		denied  bool
	}{
		{name: "zoned ipv6 loopback", address: "[::1%x.allowed.example]:80", denied: true},
		{name: "zoned 4-in-6 rendered as ipv4", address: "127.0.0.1%x.allowed.example:80", denied: true},
		{name: "zoned 4-in-6 bracketed", address: "[::ffff:127.0.0.1%eth0]:80", denied: true},
		{name: "zoned public ipv6", address: "[2001:db8::1%eth0]:80", denied: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := g.DialControl("tcp", tc.address, nil)
			if tc.denied {
				require.True(t, IsDenyError(err), "err=%v", err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestIsDenied_Zoned(t *testing.T) {
	g, err := New([]string{"::1/128", "127.0.0.0/8"})
	require.NoError(t, err)
	require.True(t, g.IsDenied(netip.MustParseAddr("::1%eth0")))
	require.True(t, g.IsDenied(netip.MustParseAddr("::ffff:127.0.0.1%eth0")))
}

func TestDialControl_EmptyGuardNoop(t *testing.T) {
	g, err := New(nil)
	require.NoError(t, err)
	require.NoError(t, g.DialControl("tcp", "127.0.0.1:443", nil))
}

func TestDialControl_NilGuardNoop(t *testing.T) {
	var g *Guard
	require.NoError(t, g.DialControl("tcp", "127.0.0.1:443", nil))
}
