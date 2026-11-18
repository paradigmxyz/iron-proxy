package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoad_ExtraTunnelListen(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		cfg, err := Load(strings.NewReader(validYAML() + `
proxy:
  tunnel_listen: "127.0.0.1:3128"
`))
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1:3128", cfg.Proxy.TunnelListen)
		require.Empty(t, cfg.Proxy.ExtraTunnelListen)
	})

	t.Run("listed", func(t *testing.T) {
		cfg, err := Load(strings.NewReader(validYAML() + `
proxy:
  tunnel_listen: "127.0.0.1:3128"
  extra_tunnel_listen: ["10.250.255.1:3128", "[fd00::1]:3128"]
`))
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1:3128", cfg.Proxy.TunnelListen)
		require.Equal(t, []string{"10.250.255.1:3128", "[fd00::1]:3128"}, cfg.Proxy.ExtraTunnelListen)
	})

	for _, tt := range []struct {
		name, proxy, wantErr string
	}{
		{
			name:    "without tunnel_listen",
			proxy:   `extra_tunnel_listen: ["10.250.255.1:3128"]`,
			wantErr: "proxy.extra_tunnel_listen requires proxy.tunnel_listen",
		},
		{
			name: "no port",
			proxy: `tunnel_listen: "127.0.0.1:3128"
  extra_tunnel_listen: ["10.250.255.1"]`,
			wantErr: "proxy.extra_tunnel_listen[0]",
		},
		{
			name: "the tunnel_listen again",
			proxy: `tunnel_listen: "127.0.0.1:3128"
  extra_tunnel_listen: ["127.0.0.1:3128"]`,
			wantErr: `proxy.extra_tunnel_listen[0]: "127.0.0.1:3128" is listed twice`,
		},
		{
			name: "repeated",
			proxy: `tunnel_listen: "127.0.0.1:3128"
  extra_tunnel_listen: ["10.250.255.1:3128", "10.250.255.1:3128"]`,
			wantErr: `proxy.extra_tunnel_listen[1]: "10.250.255.1:3128" is listed twice`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(validYAML() + "\nproxy:\n  " + tt.proxy + "\n"))
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestLoadConfig_EnvExtraTunnelListen(t *testing.T) {
	setEnvs(t, map[string]string{
		"IRON_DNS_PROXY_IP":              "127.0.0.1",
		"IRON_TLS_CA_CERT":               "/ca.pem",
		"IRON_TLS_CA_KEY":                "/ca-key.pem",
		"IRON_PROXY_TUNNEL_LISTEN":       "127.0.0.1:3128",
		"IRON_PROXY_EXTRA_TUNNEL_LISTEN": "10.250.255.1:3128, 10.250.255.2:3128",
	})
	cfg, err := LoadConfig("")
	require.NoError(t, err)
	require.Equal(t, []string{"10.250.255.1:3128", "10.250.255.2:3128"}, cfg.Proxy.ExtraTunnelListen)

	setEnvs(t, map[string]string{
		"IRON_DNS_PROXY_IP":              "127.0.0.1",
		"IRON_TLS_CA_CERT":               "/ca.pem",
		"IRON_TLS_CA_KEY":                "/ca-key.pem",
		"IRON_PROXY_TUNNEL_LISTEN":       "127.0.0.1:3128",
		"IRON_PROXY_EXTRA_TUNNEL_LISTEN": "10.250.255.1:3128,,",
	})
	_, err = LoadConfig("")
	require.ErrorContains(t, err, "IRON_PROXY_EXTRA_TUNNEL_LISTEN: empty address entry")
}
