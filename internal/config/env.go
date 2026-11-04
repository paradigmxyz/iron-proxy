package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
)

// applyEnvOverrides layers IRON_* environment variables on top of an existing
// Config. Only non-empty environment variables override the corresponding field.
func applyEnvOverrides(cfg *Config) error {
	if v := os.Getenv("IRON_DNS_ENABLED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("IRON_DNS_ENABLED: %w", err)
		}
		cfg.DNS.Enabled = &b
	}
	if v := os.Getenv("IRON_DNS_LISTEN"); v != "" {
		cfg.DNS.Listen = v
	}
	if v := os.Getenv("IRON_DNS_PROXY_IP"); v != "" {
		cfg.DNS.ProxyIP = v
	}
	if v := os.Getenv("IRON_DNS_UPSTREAM_RESOLVER"); v != "" {
		cfg.DNS.UpstreamResolver = v
	}
	if v := os.Getenv("IRON_PROXY_HTTP_LISTEN"); v != "" {
		cfg.Proxy.HTTPListen = v
	}
	if v := os.Getenv("IRON_PROXY_HTTPS_LISTEN"); v != "" {
		cfg.Proxy.HTTPSListen = v
	}
	if v := os.Getenv("IRON_PROXY_TUNNEL_LISTEN"); v != "" {
		cfg.Proxy.TunnelListen = v
	}
	if v := os.Getenv("IRON_TLS_MODE"); v != "" {
		cfg.TLS.Mode = v
	}
	if v := os.Getenv("IRON_TLS_CA_CERT"); v != "" {
		cfg.TLS.CACert = v
	}
	if v := os.Getenv("IRON_TLS_CA_KEY"); v != "" {
		cfg.TLS.CAKey = v
	}
	if v := os.Getenv("IRON_METRICS_LISTEN"); v != "" {
		cfg.Metrics.Listen = v
	}
	if v := os.Getenv("IRON_MANAGEMENT_LISTEN"); v != "" {
		cfg.Management.Listen = v
	}
	if v := os.Getenv("IRON_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}

	if v := os.Getenv("IRON_PROXY_MAX_REQUEST_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("IRON_PROXY_MAX_REQUEST_BODY_BYTES: %w", err)
		}
		cfg.Proxy.MaxRequestBodyBytes = n
	}

	if v := os.Getenv("IRON_PROXY_MAX_RESPONSE_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("IRON_PROXY_MAX_RESPONSE_BODY_BYTES: %w", err)
		}
		cfg.Proxy.MaxResponseBodyBytes = n
	}

	if v := os.Getenv("IRON_TLS_CERT_CACHE_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("IRON_TLS_CERT_CACHE_SIZE: %w", err)
		}
		cfg.TLS.CertCacheSize = n
	}

	if v := os.Getenv("IRON_TLS_LEAF_CERT_EXPIRY_HOURS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("IRON_TLS_LEAF_CERT_EXPIRY_HOURS: %w", err)
		}
		cfg.TLS.LeafCertExpiryHours = n
	}

	if v := os.Getenv("IRON_PROXY_UPSTREAM_RESPONSE_HEADER_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("IRON_PROXY_UPSTREAM_RESPONSE_HEADER_TIMEOUT: %w", err)
		}
		cfg.Proxy.UpstreamResponseHeaderTimeout = Duration(d)
	}

	if v := os.Getenv("IRON_PROXY_UPSTREAM_DENY_CIDRS"); v != "" {
		cidrs, err := splitCIDREnvList(v)
		if err != nil {
			return fmt.Errorf("IRON_PROXY_UPSTREAM_DENY_CIDRS: %w", err)
		}
		if err := dnsguard.ValidateCIDRs(cidrs); err != nil {
			return fmt.Errorf("IRON_PROXY_UPSTREAM_DENY_CIDRS: %w", err)
		}
		cfg.Proxy.UpstreamDenyCIDRs.Values = cidrs
		cfg.Proxy.UpstreamDenyCIDRs.Set = true
	}

	if v := os.Getenv("IRON_CONTROL_PLANE_POLL_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("IRON_CONTROL_PLANE_POLL_INTERVAL: %w", err)
		}
		cfg.ControlPlane.PollInterval = Duration(d)
	}

	return nil
}

func splitCIDREnvList(v string) ([]string, error) {
	parts := strings.Split(v, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			return nil, fmt.Errorf("empty CIDR entry")
		}
		values = append(values, trimmed)
	}
	return values, nil
}
