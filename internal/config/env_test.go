package config

import (
	"os"
	"testing"
	"time"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_EnvOnly_Defaults(t *testing.T) {
	setEnvs(t, map[string]string{
		"IRON_DNS_PROXY_IP": "127.0.0.1",
		"IRON_TLS_CA_CERT":  "/ca.pem",
		"IRON_TLS_CA_KEY":   "/ca-key.pem",
	})

	cfg, err := LoadConfig("")
	require.NoError(t, err)

	require.Equal(t, ":53", cfg.DNS.Listen)
	require.Equal(t, "127.0.0.1", cfg.DNS.ProxyIP)
	require.Equal(t, "", cfg.DNS.UpstreamResolver)
	require.Equal(t, ":80", cfg.Proxy.HTTPListen)
	require.Equal(t, ":443", cfg.Proxy.HTTPSListen)
	require.Equal(t, "", cfg.Proxy.TunnelListen)
	require.Equal(t, int64(1<<20), cfg.Proxy.MaxRequestBodyBytes)
	require.Equal(t, int64(0), cfg.Proxy.MaxResponseBodyBytes)
	require.Equal(t, "/ca.pem", cfg.TLS.CACert)
	require.Equal(t, "/ca-key.pem", cfg.TLS.CAKey)
	require.Equal(t, 1000, cfg.TLS.CertCacheSize)
	require.Equal(t, 72, cfg.TLS.LeafCertExpiryHours)
	require.Equal(t, ":9090", cfg.Metrics.Listen)
	require.Equal(t, "info", cfg.Log.Level)
	require.Empty(t, cfg.Transforms)
	require.Equal(t, 30*time.Second, time.Duration(cfg.Proxy.UpstreamResponseHeaderTimeout))
}

func TestLoadConfig_EnvOnly_AllOverrides(t *testing.T) {
	setEnvs(t, map[string]string{
		"IRON_DNS_LISTEN":                             ":5353",
		"IRON_DNS_PROXY_IP":                           "10.0.0.1",
		"IRON_DNS_UPSTREAM_RESOLVER":                  "8.8.8.8:53",
		"IRON_PROXY_HTTP_LISTEN":                      ":8080",
		"IRON_PROXY_HTTPS_LISTEN":                     ":8443",
		"IRON_PROXY_TUNNEL_LISTEN":                    ":1080",
		"IRON_PROXY_MAX_REQUEST_BODY_BYTES":           "2097152",
		"IRON_PROXY_MAX_RESPONSE_BODY_BYTES":          "4194304",
		"IRON_PROXY_UPSTREAM_RESPONSE_HEADER_TIMEOUT": "5m",
		"IRON_PROXY_UPSTREAM_DENY_CIDRS":              "10.0.0.0/8, 192.168.0.0/16",
		"IRON_TLS_CA_CERT":                            "/custom/ca.pem",
		"IRON_TLS_CA_KEY":                             "/custom/ca-key.pem",
		"IRON_TLS_CERT_CACHE_SIZE":                    "500",
		"IRON_TLS_LEAF_CERT_EXPIRY_HOURS":             "24",
		"IRON_METRICS_LISTEN":                         ":2112",
		"IRON_LOG_LEVEL":                              "debug",
	})

	cfg, err := LoadConfig("")
	require.NoError(t, err)

	require.Equal(t, ":5353", cfg.DNS.Listen)
	require.Equal(t, "10.0.0.1", cfg.DNS.ProxyIP)
	require.Equal(t, "8.8.8.8:53", cfg.DNS.UpstreamResolver)
	require.Equal(t, ":8080", cfg.Proxy.HTTPListen)
	require.Equal(t, ":8443", cfg.Proxy.HTTPSListen)
	require.Equal(t, ":1080", cfg.Proxy.TunnelListen)
	require.Equal(t, int64(2097152), cfg.Proxy.MaxRequestBodyBytes)
	require.Equal(t, int64(4194304), cfg.Proxy.MaxResponseBodyBytes)
	require.True(t, cfg.Proxy.UpstreamDenyCIDRs.Set)
	require.Equal(t, []string{"10.0.0.0/8", "192.168.0.0/16"}, cfg.Proxy.UpstreamDenyCIDRs.Values)
	require.Equal(t, "/custom/ca.pem", cfg.TLS.CACert)
	require.Equal(t, "/custom/ca-key.pem", cfg.TLS.CAKey)
	require.Equal(t, 500, cfg.TLS.CertCacheSize)
	require.Equal(t, 24, cfg.TLS.LeafCertExpiryHours)
	require.Equal(t, ":2112", cfg.Metrics.Listen)
	require.Equal(t, "debug", cfg.Log.Level)
	require.Equal(t, 5*time.Minute, time.Duration(cfg.Proxy.UpstreamResponseHeaderTimeout))
}

func TestLoadConfig_EnvOnly_InvalidIntegers(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		value   string
		wantErr string
	}{
		{
			name:    "bad max_request_body_bytes",
			key:     "IRON_PROXY_MAX_REQUEST_BODY_BYTES",
			value:   "notanumber",
			wantErr: "IRON_PROXY_MAX_REQUEST_BODY_BYTES",
		},
		{
			name:    "bad max_response_body_bytes",
			key:     "IRON_PROXY_MAX_RESPONSE_BODY_BYTES",
			value:   "abc",
			wantErr: "IRON_PROXY_MAX_RESPONSE_BODY_BYTES",
		},
		{
			name:    "bad cert_cache_size",
			key:     "IRON_TLS_CERT_CACHE_SIZE",
			value:   "xyz",
			wantErr: "IRON_TLS_CERT_CACHE_SIZE",
		},
		{
			name:    "bad leaf_cert_expiry_hours",
			key:     "IRON_TLS_LEAF_CERT_EXPIRY_HOURS",
			value:   "1.5",
			wantErr: "IRON_TLS_LEAF_CERT_EXPIRY_HOURS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEnvs(t, map[string]string{
				tt.key: tt.value,
			})

			_, err := LoadConfig("")
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestLoadConfig_FileWithEnvOverrides(t *testing.T) {
	// Write a config file, then override some values via env.
	cfgFile := t.TempDir() + "/proxy.yaml"
	writeFile(t, cfgFile, `
dns:
  proxy_ip: "10.0.0.1"
proxy:
  http_listen: ":8080"
  https_listen: ":8443"
tls:
  ca_cert: "/file/ca.crt"
  ca_key: "/file/ca.key"
log:
  level: "debug"
`)

	// Override proxy_ip and ca_cert via env.
	setEnvs(t, map[string]string{
		"IRON_DNS_PROXY_IP": "10.0.0.99",
		"IRON_TLS_CA_CERT":  "/env/ca.crt",
	})

	cfg, err := LoadConfig(cfgFile)
	require.NoError(t, err)

	// Overridden by env.
	require.Equal(t, "10.0.0.99", cfg.DNS.ProxyIP)
	require.Equal(t, "/env/ca.crt", cfg.TLS.CACert)

	// From file (env was empty).
	require.Equal(t, ":8080", cfg.Proxy.HTTPListen)
	require.Equal(t, ":8443", cfg.Proxy.HTTPSListen)
	require.Equal(t, "/file/ca.key", cfg.TLS.CAKey)
	require.Equal(t, "debug", cfg.Log.Level)
}

func TestApplyEnvOverrides_OnlyOverridesSetVars(t *testing.T) {
	setEnvs(t, map[string]string{
		"IRON_DNS_PROXY_IP":      "10.0.0.99",
		"IRON_PROXY_HTTP_LISTEN": ":9090",
	})

	cfg := Config{
		DNS: DNS{
			Listen:  ":5353",
			ProxyIP: "10.0.0.1",
		},
		Proxy: Proxy{
			HTTPListen:  ":80",
			HTTPSListen: ":443",
		},
		TLS: TLS{
			CACert: "/original/ca.crt",
			CAKey:  "/original/ca.key",
		},
		Log: Log{
			Level: "debug",
		},
	}

	err := applyEnvOverrides(&cfg)
	require.NoError(t, err)

	// Overridden by env vars.
	require.Equal(t, "10.0.0.99", cfg.DNS.ProxyIP)
	require.Equal(t, ":9090", cfg.Proxy.HTTPListen)

	// Not overridden: env vars were empty.
	require.Equal(t, ":5353", cfg.DNS.Listen)
	require.Equal(t, ":443", cfg.Proxy.HTTPSListen)
	require.Equal(t, "/original/ca.crt", cfg.TLS.CACert)
	require.Equal(t, "/original/ca.key", cfg.TLS.CAKey)
	require.Equal(t, "debug", cfg.Log.Level)
}

func TestApplyEnvOverrides_IntegerFields(t *testing.T) {
	setEnvs(t, map[string]string{
		"IRON_PROXY_MAX_REQUEST_BODY_BYTES": "5242880",
		"IRON_TLS_CERT_CACHE_SIZE":          "2000",
		"IRON_TLS_LEAF_CERT_EXPIRY_HOURS":   "48",
	})

	cfg := Config{
		Proxy: Proxy{
			MaxRequestBodyBytes: 1024,
		},
		TLS: TLS{
			CertCacheSize:       500,
			LeafCertExpiryHours: 24,
		},
	}

	err := applyEnvOverrides(&cfg)
	require.NoError(t, err)

	require.Equal(t, int64(5242880), cfg.Proxy.MaxRequestBodyBytes)
	require.Equal(t, 2000, cfg.TLS.CertCacheSize)
	require.Equal(t, 48, cfg.TLS.LeafCertExpiryHours)
}

func TestApplyEnvOverrides_InvalidInteger(t *testing.T) {
	setEnvs(t, map[string]string{
		"IRON_PROXY_MAX_REQUEST_BODY_BYTES": "notanumber",
	})

	var cfg Config
	err := applyEnvOverrides(&cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "IRON_PROXY_MAX_REQUEST_BODY_BYTES")
}

func TestApplyEnvOverrides_UpstreamResponseHeaderTimeout(t *testing.T) {
	t.Run("env override applied", func(t *testing.T) {
		setEnvs(t, map[string]string{
			"IRON_PROXY_UPSTREAM_RESPONSE_HEADER_TIMEOUT": "2m",
		})

		var cfg Config
		require.NoError(t, applyEnvOverrides(&cfg))
		require.Equal(t, 2*time.Minute, time.Duration(cfg.Proxy.UpstreamResponseHeaderTimeout))
	})

	t.Run("env override beats yaml value", func(t *testing.T) {
		setEnvs(t, map[string]string{
			"IRON_PROXY_UPSTREAM_RESPONSE_HEADER_TIMEOUT": "10s",
		})

		cfg := Config{Proxy: Proxy{UpstreamResponseHeaderTimeout: Duration(time.Minute)}}
		require.NoError(t, applyEnvOverrides(&cfg))
		require.Equal(t, 10*time.Second, time.Duration(cfg.Proxy.UpstreamResponseHeaderTimeout))
	})

	t.Run("invalid duration rejected", func(t *testing.T) {
		setEnvs(t, map[string]string{
			"IRON_PROXY_UPSTREAM_RESPONSE_HEADER_TIMEOUT": "not-a-duration",
		})

		var cfg Config
		err := applyEnvOverrides(&cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "IRON_PROXY_UPSTREAM_RESPONSE_HEADER_TIMEOUT")
	})
}

func TestApplyEnvOverrides_UpstreamDenyCIDRs(t *testing.T) {
	t.Run("env override applied", func(t *testing.T) {
		setEnvs(t, map[string]string{
			"IRON_PROXY_UPSTREAM_DENY_CIDRS": "10.0.0.0/8,192.168.0.0/16",
		})

		var cfg Config
		require.NoError(t, applyEnvOverrides(&cfg))
		require.True(t, cfg.Proxy.UpstreamDenyCIDRs.Set)
		require.Equal(t, []string{"10.0.0.0/8", "192.168.0.0/16"}, cfg.Proxy.UpstreamDenyCIDRs.Values)
	})

	t.Run("env override beats yaml value", func(t *testing.T) {
		setEnvs(t, map[string]string{
			"IRON_PROXY_UPSTREAM_DENY_CIDRS": "10.0.0.0/8",
		})

		cfg := Config{Proxy: Proxy{UpstreamDenyCIDRs: CIDRList{
			Values: []string{"169.254.169.254/32"},
			Set:    true,
		}}}
		require.NoError(t, applyEnvOverrides(&cfg))
		require.True(t, cfg.Proxy.UpstreamDenyCIDRs.Set)
		require.Equal(t, []string{"10.0.0.0/8"}, cfg.Proxy.UpstreamDenyCIDRs.Values)
	})

	t.Run("unset keeps default", func(t *testing.T) {
		setEnvs(t, map[string]string{})

		cfg, err := LoadConfig("")
		require.NoError(t, err)
		require.True(t, cfg.Proxy.UpstreamDenyCIDRs.Set)
		require.Equal(t, dnsguard.DefaultDenyCIDRs, cfg.Proxy.UpstreamDenyCIDRs.Values)
	})

	t.Run("invalid cidr rejected", func(t *testing.T) {
		setEnvs(t, map[string]string{
			"IRON_PROXY_UPSTREAM_DENY_CIDRS": "1.2.3.4",
		})

		var cfg Config
		err := applyEnvOverrides(&cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "IRON_PROXY_UPSTREAM_DENY_CIDRS")
		require.Contains(t, err.Error(), "must be CIDR notation")
	})

	t.Run("empty entry rejected", func(t *testing.T) {
		setEnvs(t, map[string]string{
			"IRON_PROXY_UPSTREAM_DENY_CIDRS": "10.0.0.0/8,",
		})

		var cfg Config
		err := applyEnvOverrides(&cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "IRON_PROXY_UPSTREAM_DENY_CIDRS")
		require.Contains(t, err.Error(), "empty CIDR entry")
	})
}

func TestApplyEnvOverrides_ControlPlanePollInterval(t *testing.T) {
	t.Run("env override applied", func(t *testing.T) {
		setEnvs(t, map[string]string{
			"IRON_CONTROL_PLANE_POLL_INTERVAL": "15s",
		})

		var cfg Config
		require.NoError(t, applyEnvOverrides(&cfg))
		require.Equal(t, 15*time.Second, time.Duration(cfg.ControlPlane.PollInterval))
	})

	t.Run("env override beats yaml value", func(t *testing.T) {
		setEnvs(t, map[string]string{
			"IRON_CONTROL_PLANE_POLL_INTERVAL": "20s",
		})

		cfg := Config{ControlPlane: ControlPlane{PollInterval: Duration(time.Minute)}}
		require.NoError(t, applyEnvOverrides(&cfg))
		require.Equal(t, 20*time.Second, time.Duration(cfg.ControlPlane.PollInterval))
	})

	t.Run("invalid duration rejected", func(t *testing.T) {
		setEnvs(t, map[string]string{
			"IRON_CONTROL_PLANE_POLL_INTERVAL": "not-a-duration",
		})

		var cfg Config
		err := applyEnvOverrides(&cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "IRON_CONTROL_PLANE_POLL_INTERVAL")
	})
}

func TestApplyEnvOverrides_DNSEnabled(t *testing.T) {
	t.Run("false disables dns", func(t *testing.T) {
		setEnvs(t, map[string]string{"IRON_DNS_ENABLED": "false"})

		var cfg Config
		require.NoError(t, applyEnvOverrides(&cfg))
		require.NotNil(t, cfg.DNS.Enabled)
		require.False(t, cfg.DNS.IsEnabled())
	})

	t.Run("true enables dns", func(t *testing.T) {
		setEnvs(t, map[string]string{"IRON_DNS_ENABLED": "true"})

		var cfg Config
		require.NoError(t, applyEnvOverrides(&cfg))
		require.NotNil(t, cfg.DNS.Enabled)
		require.True(t, cfg.DNS.IsEnabled())
	})

	t.Run("unset defaults to enabled", func(t *testing.T) {
		setEnvs(t, map[string]string{})

		var cfg Config
		require.NoError(t, applyEnvOverrides(&cfg))
		require.Nil(t, cfg.DNS.Enabled)
		require.True(t, cfg.DNS.IsEnabled())
	})

	t.Run("invalid bool rejected", func(t *testing.T) {
		setEnvs(t, map[string]string{"IRON_DNS_ENABLED": "maybe"})

		var cfg Config
		err := applyEnvOverrides(&cfg)
		require.ErrorContains(t, err, "IRON_DNS_ENABLED")
	})
}

// TestLoadConfig_DNSDisabled_NoListenDefault_NoProxyIPRequired verifies that
// disabling DNS via env skips the :53 listen default and lifts the proxy_ip
// requirement, so a DNS-less proxy can be configured entirely from env vars.
func TestLoadConfig_DNSDisabled_NoListenDefault_NoProxyIPRequired(t *testing.T) {
	setEnvs(t, map[string]string{
		"IRON_DNS_ENABLED": "false",
		"IRON_TLS_CA_CERT": "/ca.pem",
		"IRON_TLS_CA_KEY":  "/ca-key.pem",
	})

	cfg, err := LoadConfig("")
	require.NoError(t, err)
	require.False(t, cfg.DNS.IsEnabled())
	require.Equal(t, "", cfg.DNS.Listen)
	require.Equal(t, "", cfg.DNS.ProxyIP)
	require.NoError(t, Validate(cfg))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// setEnvs sets environment variables for the duration of the test, clearing
// all IRON_* env vars first to ensure a clean slate.
func setEnvs(t *testing.T, envs map[string]string) {
	t.Helper()

	// Clear all IRON_* env vars to prevent cross-test leakage.
	ironKeys := []string{
		"IRON_SSH_CONFIG_JSON",
		"IRON_DNS_ENABLED",
		"IRON_DNS_LISTEN",
		"IRON_DNS_PROXY_IP",
		"IRON_DNS_UPSTREAM_RESOLVER",
		"IRON_PROXY_HTTP_LISTEN",
		"IRON_PROXY_HTTPS_LISTEN",
		"IRON_PROXY_TUNNEL_LISTEN",
		"IRON_PROXY_MAX_REQUEST_BODY_BYTES",
		"IRON_PROXY_MAX_RESPONSE_BODY_BYTES",
		"IRON_PROXY_UPSTREAM_RESPONSE_HEADER_TIMEOUT",
		"IRON_PROXY_UPSTREAM_DENY_CIDRS",
		"IRON_TLS_CA_CERT",
		"IRON_TLS_CA_KEY",
		"IRON_TLS_CERT_CACHE_SIZE",
		"IRON_TLS_LEAF_CERT_EXPIRY_HOURS",
		"IRON_METRICS_LISTEN",
		"IRON_LOG_LEVEL",
	}
	for _, k := range ironKeys {
		t.Setenv(k, "")
	}

	for k, v := range envs {
		t.Setenv(k, v)
	}
}

func TestSSHEnvironmentConfig(t *testing.T) {
	setEnvs(t, map[string]string{"IRON_SSH_CONFIG_JSON": `{"listen":"127.0.0.1:2222"}`})
	cfg, err := LoadConfig("")
	require.NoError(t, err)
	var ssh struct {
		Listen string `yaml:"listen"`
	}
	require.NoError(t, cfg.SSH.Decode(&ssh))
	require.Equal(t, "127.0.0.1:2222", ssh.Listen)
	t.Setenv("IRON_SSH_CONFIG_JSON", "sensitive-value: [")
	_, err = LoadConfig("")
	require.EqualError(t, err, "IRON_SSH_CONFIG_JSON is invalid")
}
