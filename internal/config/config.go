// Package config handles parsing and validation of iron-proxy's YAML configuration.
package config

import (
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
)

const (
	// DefaultUpstreamResponseHeaderTimeout is the default cap on how long the
	// proxy waits for upstream response headers before returning 502.
	DefaultUpstreamResponseHeaderTimeout = 30 * time.Second

	// DefaultControlPlanePollInterval is the default base interval between
	// control-plane sync calls. The poller applies jitter around this value.
	DefaultControlPlanePollInterval = 10 * time.Second
)

// Duration is a time.Duration that decodes YAML strings using
// time.ParseDuration ("30s", "5m", "2h"). The zero value indicates "unset"
// so applyDefaults can fill in a default.
type Duration time.Duration

// UnmarshalYAML decodes a Go duration string into a Duration.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// Config is the top-level configuration for iron-proxy.
//
// The MCP block is parsed as a raw yaml.Node and decoded by internal/mcp at
// pipeline-build time, mirroring how Transforms are handled: the config
// package stays decoupled from the consumer's typed schema, and validation
// errors surface where the value is actually used.
type Config struct {
	DNS          DNS          `yaml:"dns"`
	Proxy        Proxy        `yaml:"proxy"`
	TLS          TLS          `yaml:"tls"`
	Transforms   []Transform  `yaml:"transforms"`
	MCP          yaml.Node    `yaml:"mcp"`
	MCPGateway   yaml.Node    `yaml:"mcp_gateway"`
	Postgres     yaml.Node    `yaml:"postgres"`
	Metrics      Metrics      `yaml:"metrics"`
	Management   Management   `yaml:"management"`
	ControlPlane ControlPlane `yaml:"control_plane"`
	Log          Log          `yaml:"log"`
}

// DNS configures the built-in DNS server.
type DNS struct {
	// Enabled controls whether the built-in DNS server runs. A nil pointer
	// (the field omitted) defaults to true, preserving historical behavior.
	// Set it to false (or IRON_DNS_ENABLED=false) to disable DNS interception
	// entirely — useful when clients reach the proxy via explicit
	// HTTP(S)_PROXY settings rather than DNS redirection. When disabled,
	// proxy_ip is not required.
	Enabled          *bool       `yaml:"enabled"`
	Listen           string      `yaml:"listen"`
	ProxyIP          string      `yaml:"proxy_ip"`
	UpstreamResolver string      `yaml:"upstream_resolver"`
	Passthrough      []string    `yaml:"passthrough"`
	Records          []DNSRecord `yaml:"records"`
}

// IsEnabled reports whether the DNS server should run. DNS is on unless
// explicitly disabled.
func (d DNS) IsEnabled() bool {
	return d.Enabled == nil || *d.Enabled
}

// DNSRecord is a static DNS record entry.
type DNSRecord struct {
	Name  string `yaml:"name"`
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

// Proxy configures the HTTP/HTTPS listener addresses.
type Proxy struct {
	HTTPListen           string `yaml:"http_listen"`
	HTTPSListen          string `yaml:"https_listen"`
	TunnelListen         string `yaml:"tunnel_listen"`
	MaxRequestBodyBytes  int64  `yaml:"max_request_body_bytes"`
	MaxResponseBodyBytes int64  `yaml:"max_response_body_bytes"`
	// UpstreamResponseHeaderTimeout caps how long the proxy waits for an
	// upstream response's headers before returning 502. Accepts Go duration
	// syntax: "30s" (default), "5m", "2h". Useful for upstream endpoints
	// (e.g. LLM context compaction) that legitimately take longer than the
	// 30-second default to begin replying.
	UpstreamResponseHeaderTimeout Duration `yaml:"upstream_response_header_timeout"`
	// UpstreamDenyCIDRs lists CIDR ranges the proxy refuses to dial. Enforced
	// at connect time against the resolved address. When unset, a secure
	// default (IMDS + loopback) is applied; set to an empty list to disable.
	UpstreamDenyCIDRs CIDRList `yaml:"upstream_deny_cidrs"`
	// UpstreamProxy routes iron-proxy's own outbound connections through an
	// upstream SOCKS5/HTTP CONNECT proxy. The standard HTTP_PROXY/HTTPS_PROXY/
	// NO_PROXY environment variables override these fields when set.
	UpstreamProxy UpstreamProxy `yaml:"upstream_proxy"`
}

// CIDRList is a list of CIDR strings whose presence in YAML is distinguishable
// from absence: an explicit empty list opts out of any default population,
// while an unset field signals "apply the default".
type CIDRList struct {
	Values []string
	Set    bool
}

// UnmarshalYAML records that the field was present in the source document,
// even when the value is an empty list.
func (l *CIDRList) UnmarshalYAML(value *yaml.Node) error {
	l.Set = true
	return value.Decode(&l.Values)
}

// TLS configures certificate authority and cert caching for MITM.
type TLS struct {
	// Mode selects how the HTTPS listener handles TLS connections.
	// "mitm" (default): terminate TLS, mint a leaf cert signed by the configured
	// CA, and run the full request/response pipeline.
	// "sni-only": peek the ClientHello SNI, run the pipeline with a host-only
	// synthetic request, and TCP-passthrough to the upstream. No CA required.
	Mode                string `yaml:"mode"`
	CACert              string `yaml:"ca_cert"`
	CAKey               string `yaml:"ca_key"`
	CertCacheSize       int    `yaml:"cert_cache_size"`
	LeafCertExpiryHours int    `yaml:"leaf_cert_expiry_hours"`
}

// TLS mode values.
const (
	TLSModeMITM    = "mitm"
	TLSModeSNIOnly = "sni-only"
)

// Transform is a named transform with arbitrary config.
// Config is a raw yaml.Node so each transform can decode it into its own typed struct.
type Transform struct {
	Name   string    `yaml:"name"`
	Config yaml.Node `yaml:"config"`
}

// Metrics configures the OpenTelemetry/Prometheus metrics endpoint.
type Metrics struct {
	Listen string `yaml:"listen"`
}

// Management configures the optional operator-facing HTTP API.
//
// When Listen is empty (the default) the management server is disabled.
// When Listen is set, requests are authenticated with a bearer token whose
// value is read from the env var named in APIKeyEnv.
type Management struct {
	Listen    string `yaml:"listen"`
	APIKeyEnv string `yaml:"api_key_env"`
}

// ControlPlane configures managed-mode control-plane behavior.
type ControlPlane struct {
	// PollInterval is the base interval between control-plane sync calls.
	// Accepts Go duration syntax: "10s" (default), "1m", "500ms".
	// The poller applies jitter around this value.
	PollInterval Duration `yaml:"poll_interval"`
}

// Log configures structured logging.
type Log struct {
	Level string `yaml:"level"`
}

// LoadConfig is the primary entry point for building a Config. It parses an
// optional YAML config file, layers in IRON_* environment variable overrides,
// and applies defaults. If path is empty, the config is built entirely from
// environment variables and defaults.
//
// Validation is intentionally not performed here so that callers can populate
// additional fields (e.g. from a control plane sync) before calling Validate.
func LoadConfig(path string) (*Config, error) {
	var cfg Config
	if path != "" {
		parsed, err := parseFileOrS3(path)
		if err != nil {
			return nil, err
		}
		cfg = *parsed
	}

	if err := applyEnvOverrides(&cfg); err != nil {
		return nil, err
	}

	applyDefaults(&cfg)

	return &cfg, nil
}

// Load parses a YAML config from the given reader, applies defaults, and
// validates. This is a convenience for tests and standalone readers.
func Load(r io.Reader) (*Config, error) {
	cfg, err := parse(r)
	if err != nil {
		return nil, err
	}
	applyDefaults(cfg)
	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}
	return cfg, nil
}

func parse(r io.Reader) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.DNS.IsEnabled() && cfg.DNS.Listen == "" {
		cfg.DNS.Listen = ":53"
	}
	if cfg.Proxy.HTTPListen == "" {
		cfg.Proxy.HTTPListen = ":80"
	}
	if cfg.Proxy.HTTPSListen == "" {
		cfg.Proxy.HTTPSListen = ":443"
	}
	if cfg.Proxy.MaxRequestBodyBytes == 0 {
		cfg.Proxy.MaxRequestBodyBytes = 1 << 20 // 1 MiB
	}
	// MaxResponseBodyBytes defaults to 0 (uncapped).
	if cfg.Proxy.UpstreamResponseHeaderTimeout == 0 {
		cfg.Proxy.UpstreamResponseHeaderTimeout = Duration(DefaultUpstreamResponseHeaderTimeout)
	}
	if !cfg.Proxy.UpstreamDenyCIDRs.Set {
		cfg.Proxy.UpstreamDenyCIDRs.Values = append([]string(nil), dnsguard.DefaultDenyCIDRs...)
		cfg.Proxy.UpstreamDenyCIDRs.Set = true
	}
	if cfg.TLS.Mode == "" {
		cfg.TLS.Mode = TLSModeMITM
	}
	if cfg.TLS.CertCacheSize == 0 {
		cfg.TLS.CertCacheSize = 1000
	}
	if cfg.TLS.LeafCertExpiryHours == 0 {
		cfg.TLS.LeafCertExpiryHours = 72
	}
	if cfg.Metrics.Listen == "" {
		cfg.Metrics.Listen = ":9090"
	}
	if cfg.Management.Listen != "" && cfg.Management.APIKeyEnv == "" {
		cfg.Management.APIKeyEnv = "IRON_MANAGEMENT_API_KEY"
	}
	if cfg.ControlPlane.PollInterval == 0 {
		cfg.ControlPlane.PollInterval = Duration(DefaultControlPlanePollInterval)
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
}

// Validate checks required fields and value constraints.
func Validate(cfg *Config) error {
	if cfg.DNS.IsEnabled() && cfg.DNS.ProxyIP == "" {
		return fmt.Errorf("dns.proxy_ip is required")
	}

	switch cfg.TLS.Mode {
	case TLSModeMITM:
		if cfg.TLS.CACert == "" {
			return fmt.Errorf("tls.ca_cert is required")
		}
		if cfg.TLS.CAKey == "" {
			return fmt.Errorf("tls.ca_key is required")
		}
	case TLSModeSNIOnly:
		// CA cert/key are ignored in sni-only mode; no requirement.
	default:
		return fmt.Errorf("tls.mode must be %q or %q; got %q", TLSModeMITM, TLSModeSNIOnly, cfg.TLS.Mode)
	}

	if _, err := parseLogLevel(cfg.Log.Level); err != nil {
		return fmt.Errorf("log.level: %w", err)
	}

	if cfg.Proxy.UpstreamResponseHeaderTimeout <= 0 {
		return fmt.Errorf("proxy.upstream_response_header_timeout must be positive; got %s", time.Duration(cfg.Proxy.UpstreamResponseHeaderTimeout))
	}
	if cfg.ControlPlane.PollInterval <= 0 {
		return fmt.Errorf("control_plane.poll_interval must be positive; got %s", time.Duration(cfg.ControlPlane.PollInterval))
	}

	if err := dnsguard.ValidateCIDRs(cfg.Proxy.UpstreamDenyCIDRs.Values); err != nil {
		return fmt.Errorf("proxy.upstream_deny_cidrs: %w", err)
	}

	if cfg.Management.Listen != "" {
		if cfg.Management.APIKeyEnv == "" {
			return fmt.Errorf("management.api_key_env is required when management.listen is set")
		}
		if os.Getenv(cfg.Management.APIKeyEnv) == "" {
			return fmt.Errorf("management.api_key_env %q is not set in the environment", cfg.Management.APIKeyEnv)
		}
	}

	for i, rec := range cfg.DNS.Records {
		if rec.Name == "" {
			return fmt.Errorf("dns.records[%d].name is required", i)
		}
		validTypes := map[string]bool{"A": true, "CNAME": true}
		if !validTypes[rec.Type] {
			return fmt.Errorf("dns.records[%d].type must be A or CNAME; got %q", i, rec.Type)
		}
		if rec.Value == "" {
			return fmt.Errorf("dns.records[%d].value is required", i)
		}
	}

	return nil
}
