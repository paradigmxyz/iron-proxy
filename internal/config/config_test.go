package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
)

func validYAML() string {
	return `
dns:
  proxy_ip: "10.16.0.1"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
}

func TestParse_NoDefaultsOrValidation(t *testing.T) {
	// parse should not apply defaults or validate.
	yaml := `
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
	cfg, err := parse(strings.NewReader(yaml))
	require.NoError(t, err)

	// dns.proxy_ip is missing but parse should not error.
	require.Equal(t, "", cfg.DNS.ProxyIP)

	// Defaults should not be applied.
	require.Equal(t, "", cfg.DNS.Listen)
	require.Equal(t, "", cfg.Proxy.HTTPListen)
	require.Equal(t, "", cfg.Log.Level)
}

func TestLoad_ValidConfig(t *testing.T) {
	cfg, err := Load(strings.NewReader(validYAML()))
	require.NoError(t, err)

	require.Equal(t, "10.16.0.1", cfg.DNS.ProxyIP)
	require.Equal(t, "/tmp/ca.crt", cfg.TLS.CACert)
	require.Equal(t, "/tmp/ca.key", cfg.TLS.CAKey)
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load(strings.NewReader(validYAML()))
	require.NoError(t, err)

	require.Equal(t, ":53", cfg.DNS.Listen)
	require.Equal(t, ":80", cfg.Proxy.HTTPListen)
	require.Equal(t, ":443", cfg.Proxy.HTTPSListen)
	require.Equal(t, 1000, cfg.TLS.CertCacheSize)
	require.Equal(t, ":9090", cfg.Metrics.Listen)
	require.Equal(t, "info", cfg.Log.Level)
}

func TestLoad_OverrideDefaults(t *testing.T) {
	yaml := `
dns:
  listen: ":5353"
  proxy_ip: "10.0.0.1"
proxy:
  http_listen: ":8080"
  https_listen: ":8443"
tls:
  ca_cert: "/etc/ca.crt"
  ca_key: "/etc/ca.key"
  cert_cache_size: 500
metrics:
  listen: ":9191"
log:
  level: "debug"
`
	cfg, err := Load(strings.NewReader(yaml))
	require.NoError(t, err)

	require.Equal(t, ":5353", cfg.DNS.Listen)
	require.Equal(t, ":8080", cfg.Proxy.HTTPListen)
	require.Equal(t, ":8443", cfg.Proxy.HTTPSListen)
	require.Equal(t, 500, cfg.TLS.CertCacheSize)
	require.Equal(t, ":9191", cfg.Metrics.Listen)
	require.Equal(t, "debug", cfg.Log.Level)
}

func TestLoad_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "missing proxy_ip",
			yaml: `
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`,
			wantErr: "dns.proxy_ip is required",
		},
		{
			name: "missing ca_cert",
			yaml: `
dns:
  proxy_ip: "10.0.0.1"
tls:
  ca_key: "/tmp/ca.key"
`,
			wantErr: "tls.ca_cert is required",
		},
		{
			name: "missing ca_key",
			yaml: `
dns:
  proxy_ip: "10.0.0.1"
tls:
  ca_cert: "/tmp/ca.crt"
`,
			wantErr: "tls.ca_key is required",
		},
		{
			name: "invalid log level",
			yaml: `
dns:
  proxy_ip: "10.0.0.1"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
log:
  level: "trace"
`,
			wantErr: "unknown log level",
		},
		{
			name: "dns record missing name",
			yaml: `
dns:
  proxy_ip: "10.0.0.1"
  records:
    - type: A
      value: "1.2.3.4"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`,
			wantErr: "dns.records[0].name is required",
		},
		{
			name: "dns record invalid type",
			yaml: `
dns:
  proxy_ip: "10.0.0.1"
  records:
    - name: "example.com"
      type: MX
      value: "mail.example.com"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`,
			wantErr: "dns.records[0].type must be A or CNAME",
		},
		{
			name: "dns record missing value",
			yaml: `
dns:
  proxy_ip: "10.0.0.1"
  records:
    - name: "example.com"
      type: A
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`,
			wantErr: "dns.records[0].value is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(tt.yaml))
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestLoad_UnknownFields(t *testing.T) {
	yaml := `
dns:
  proxy_ip: "10.0.0.1"
  unknown_field: true
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
	_, err := Load(strings.NewReader(yaml))
	require.Error(t, err)
	require.Contains(t, err.Error(), "parsing config")
}

func TestLoad_InvalidYAML(t *testing.T) {
	_, err := Load(strings.NewReader(`{{{`))
	require.Error(t, err)
}

func TestLoad_Transforms(t *testing.T) {
	yaml := `
dns:
  proxy_ip: "10.0.0.1"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
transforms:
  - name: allowlist
    config:
      domains:
        - "*.example.com"
      cidrs:
        - "10.0.0.0/8"
`
	cfg, err := Load(strings.NewReader(yaml))
	require.NoError(t, err)
	require.Len(t, cfg.Transforms, 1)
	require.Equal(t, "allowlist", cfg.Transforms[0].Name)

	// Decode the raw yaml.Node into a typed struct, as a real transform would.
	var allowCfg struct {
		Domains []string `yaml:"domains"`
		CIDRs   []string `yaml:"cidrs"`
	}
	require.NoError(t, cfg.Transforms[0].Config.Decode(&allowCfg))
	require.Equal(t, []string{"*.example.com"}, allowCfg.Domains)
	require.Equal(t, []string{"10.0.0.0/8"}, allowCfg.CIDRs)
}

func TestLoad_DNSDisabled(t *testing.T) {
	t.Run("disabled skips proxy_ip requirement and listen default", func(t *testing.T) {
		yaml := `
dns:
  enabled: false
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		cfg, err := Load(strings.NewReader(yaml))
		require.NoError(t, err)
		require.NotNil(t, cfg.DNS.Enabled)
		require.False(t, cfg.DNS.IsEnabled())
		require.Equal(t, "", cfg.DNS.Listen)
	})

	t.Run("enabled by default still requires proxy_ip", func(t *testing.T) {
		yaml := `
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		_, err := Load(strings.NewReader(yaml))
		require.ErrorContains(t, err, "dns.proxy_ip is required")
	})

	t.Run("explicitly enabled gets listen default", func(t *testing.T) {
		yaml := `
dns:
  enabled: true
  proxy_ip: "10.0.0.1"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		cfg, err := Load(strings.NewReader(yaml))
		require.NoError(t, err)
		require.True(t, cfg.DNS.IsEnabled())
		require.Equal(t, ":53", cfg.DNS.Listen)
	})
}

func TestLoad_SNIOnlyMode(t *testing.T) {
	t.Run("ca cert not required", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
tls:
  mode: "sni-only"
`
		cfg, err := Load(strings.NewReader(yaml))
		require.NoError(t, err)
		require.Equal(t, "sni-only", cfg.TLS.Mode)
		require.Equal(t, "", cfg.TLS.CACert)
	})

	t.Run("unknown mode rejected", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
tls:
  mode: "hybrid"
`
		_, err := Load(strings.NewReader(yaml))
		require.Error(t, err)
		require.Contains(t, err.Error(), "tls.mode")
	})

	t.Run("mitm mode still requires ca_cert", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
tls:
  mode: "mitm"
`
		_, err := Load(strings.NewReader(yaml))
		require.Error(t, err)
		require.Contains(t, err.Error(), "tls.ca_cert")
	})
}

func TestLoad_DNSPassthroughAndRecords(t *testing.T) {
	yaml := `
dns:
  proxy_ip: "10.0.0.1"
  passthrough:
    - "*.internal.corp"
    - "metadata.google.internal"
  records:
    - name: "internal.example.com"
      type: A
      value: "10.0.0.5"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
	cfg, err := Load(strings.NewReader(yaml))
	require.NoError(t, err)
	require.Equal(t, []string{"*.internal.corp", "metadata.google.internal"}, cfg.DNS.Passthrough)
	require.Len(t, cfg.DNS.Records, 1)
	require.Equal(t, "internal.example.com", cfg.DNS.Records[0].Name)
	require.Equal(t, "A", cfg.DNS.Records[0].Type)
	require.Equal(t, "10.0.0.5", cfg.DNS.Records[0].Value)
}

func TestLoad_UpstreamDenyCIDRs(t *testing.T) {
	t.Run("default applied when unset", func(t *testing.T) {
		cfg, err := Load(strings.NewReader(validYAML()))
		require.NoError(t, err)
		require.True(t, cfg.Proxy.UpstreamDenyCIDRs.Set)
		require.Equal(t, dnsguard.DefaultDenyCIDRs, cfg.Proxy.UpstreamDenyCIDRs.Values)
	})

	t.Run("explicit empty list opts out", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
proxy:
  upstream_deny_cidrs: []
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		cfg, err := Load(strings.NewReader(yaml))
		require.NoError(t, err)
		require.True(t, cfg.Proxy.UpstreamDenyCIDRs.Set)
		require.Empty(t, cfg.Proxy.UpstreamDenyCIDRs.Values)
	})

	t.Run("explicit list replaces defaults", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
proxy:
  upstream_deny_cidrs:
    - "169.254.169.254/32"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		cfg, err := Load(strings.NewReader(yaml))
		require.NoError(t, err)
		require.Equal(t, []string{"169.254.169.254/32"}, cfg.Proxy.UpstreamDenyCIDRs.Values)
	})

	t.Run("bare IP rejected", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
proxy:
  upstream_deny_cidrs:
    - "1.2.3.4"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		_, err := Load(strings.NewReader(yaml))
		require.Error(t, err)
		require.Contains(t, err.Error(), "proxy.upstream_deny_cidrs")
		require.Contains(t, err.Error(), "must be CIDR notation")
	})

	t.Run("malformed CIDR rejected", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
proxy:
  upstream_deny_cidrs:
    - "not-an-ip/24"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		_, err := Load(strings.NewReader(yaml))
		require.Error(t, err)
		require.Contains(t, err.Error(), "proxy.upstream_deny_cidrs")
	})
}

func TestLoad_UpstreamPrivateExceptions(t *testing.T) {
	yaml := validYAML() + `
proxy:
  upstream_private_exceptions:
    managed-rpc: ["10.23.4.5/32"]
`
	cfg, err := Load(strings.NewReader(yaml))
	require.NoError(t, err)
	require.Equal(t, map[string][]string{"managed-rpc": {"10.23.4.5/32"}}, cfg.Proxy.UpstreamPrivateExceptions)

	yaml = strings.Replace(yaml, "managed-rpc:", "'*':", 1)
	_, err = Load(strings.NewReader(yaml))
	require.Error(t, err)
	require.Contains(t, err.Error(), "proxy.upstream_private_exceptions")
}

func TestLoad_Management(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		cfg, err := Load(strings.NewReader(validYAML()))
		require.NoError(t, err)
		require.Equal(t, "", cfg.Management.Listen)
		require.Equal(t, "", cfg.Management.APIKeyEnv)
	})

	t.Run("api_key_env defaults when listen set", func(t *testing.T) {
		t.Setenv("IRON_MANAGEMENT_API_KEY", "secret")
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
management:
  listen: "127.0.0.1:9092"
`
		cfg, err := Load(strings.NewReader(yaml))
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1:9092", cfg.Management.Listen)
		require.Equal(t, "IRON_MANAGEMENT_API_KEY", cfg.Management.APIKeyEnv)
	})

	t.Run("api_key_env override honored", func(t *testing.T) {
		t.Setenv("CUSTOM_KEY", "secret")
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
management:
  listen: "127.0.0.1:9092"
  api_key_env: "CUSTOM_KEY"
`
		cfg, err := Load(strings.NewReader(yaml))
		require.NoError(t, err)
		require.Equal(t, "CUSTOM_KEY", cfg.Management.APIKeyEnv)
	})

	t.Run("missing env var rejected", func(t *testing.T) {
		// Ensure the default env var is unset for this test.
		t.Setenv("IRON_MANAGEMENT_API_KEY", "")
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
management:
  listen: "127.0.0.1:9092"
`
		_, err := Load(strings.NewReader(yaml))
		require.Error(t, err)
		require.Contains(t, err.Error(), "IRON_MANAGEMENT_API_KEY")
		require.Contains(t, err.Error(), "is not set")
	})
}

func TestLoad_UpstreamResponseHeaderTimeout(t *testing.T) {
	t.Run("default applied when unset", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		cfg, err := Load(strings.NewReader(yaml))
		require.NoError(t, err)
		require.Equal(t, 30*time.Second, time.Duration(cfg.Proxy.UpstreamResponseHeaderTimeout))
	})

	t.Run("valid duration accepted", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
proxy:
  upstream_response_header_timeout: "5m"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		cfg, err := Load(strings.NewReader(yaml))
		require.NoError(t, err)
		require.Equal(t, 5*time.Minute, time.Duration(cfg.Proxy.UpstreamResponseHeaderTimeout))
	})

	t.Run("invalid duration rejected at parse", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
proxy:
  upstream_response_header_timeout: "not-a-duration"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		_, err := Load(strings.NewReader(yaml))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid duration")
	})

	t.Run("negative duration rejected at validate", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
proxy:
  upstream_response_header_timeout: "-5s"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		_, err := Load(strings.NewReader(yaml))
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be positive")
	})
}

func TestLoad_ControlPlanePollInterval(t *testing.T) {
	t.Run("default applied when unset", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		cfg, err := Load(strings.NewReader(yaml))
		require.NoError(t, err)
		require.Equal(t, 10*time.Second, time.Duration(cfg.ControlPlane.PollInterval))
	})

	t.Run("valid duration accepted", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
control_plane:
  poll_interval: "30s"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		cfg, err := Load(strings.NewReader(yaml))
		require.NoError(t, err)
		require.Equal(t, 30*time.Second, time.Duration(cfg.ControlPlane.PollInterval))
	})

	t.Run("invalid duration rejected at parse", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
control_plane:
  poll_interval: "not-a-duration"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		_, err := Load(strings.NewReader(yaml))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid duration")
	})

	t.Run("negative duration rejected at validate", func(t *testing.T) {
		yaml := `
dns:
  proxy_ip: "10.0.0.1"
control_plane:
  poll_interval: "-5s"
tls:
  ca_cert: "/tmp/ca.crt"
  ca_key: "/tmp/ca.key"
`
		_, err := Load(strings.NewReader(yaml))
		require.Error(t, err)
		require.Contains(t, err.Error(), "control_plane.poll_interval must be positive")
	})
}
