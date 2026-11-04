// Command iron-proxy runs the MITM HTTP/HTTPS proxy with built-in DNS server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/controlplane"
	idns "github.com/ironsh/iron-proxy/internal/dns"
	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/management"
	"github.com/ironsh/iron-proxy/internal/mcp"
	"github.com/ironsh/iron-proxy/internal/mcpgateway"
	"github.com/ironsh/iron-proxy/internal/metrics"
	iotel "github.com/ironsh/iron-proxy/internal/otel"
	"github.com/ironsh/iron-proxy/internal/postgres"
	"github.com/ironsh/iron-proxy/internal/proxy"
	"github.com/ironsh/iron-proxy/internal/responseretry"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/version"

	// Register built-in transforms.
	_ "github.com/ironsh/iron-proxy/internal/transform/allowlist"
	_ "github.com/ironsh/iron-proxy/internal/transform/annotate"
	_ "github.com/ironsh/iron-proxy/internal/transform/awsauth"
	_ "github.com/ironsh/iron-proxy/internal/transform/bodycapture"
	_ "github.com/ironsh/iron-proxy/internal/transform/gcpauth"
	_ "github.com/ironsh/iron-proxy/internal/transform/gcpidtoken"
	_ "github.com/ironsh/iron-proxy/internal/transform/grpc"
	_ "github.com/ironsh/iron-proxy/internal/transform/headerallowlist"
	_ "github.com/ironsh/iron-proxy/internal/transform/hmacsign"
	_ "github.com/ironsh/iron-proxy/internal/transform/judge"
	_ "github.com/ironsh/iron-proxy/internal/transform/oauth"
	_ "github.com/ironsh/iron-proxy/internal/transform/secrets"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "generate-ca":
			runGenerateCA(os.Args[2:])
			return
		case "version", "--version", "-v":
			fmt.Println(version.Version)
			return
		}
	}

	configPath := flag.String("config", "", "path to iron-proxy YAML config file")
	tokenFlag := flag.String("token", "", "control plane bearer token (managed mode)")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load config: parse file (if provided) → env overrides → defaults.
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	logger, err := config.NewLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// CLI flag takes precedence over environment variable.
	proxyToken := *tokenFlag
	if proxyToken == "" {
		proxyToken = os.Getenv("IRON_PROXY_TOKEN")
	}

	// Managed mode is determined by the presence of a control plane token.
	managed := proxyToken != ""

	// Standalone mode serves /v1/reload, which re-reads the config file.
	// Managed mode serves /v1/status and /v1/sync instead: the control plane
	// stays the source of truth for config, while the sandbox control plane
	// can verify which principal's config the proxy has actually applied
	// before routing traffic through it.
	if cfg.Management.Listen != "" && !managed && *configPath == "" {
		fmt.Fprintln(os.Stderr, "error: management.listen requires --config in standalone mode; /v1/reload has no file to re-read")
		os.Exit(1)
	}

	// Both modes produce a pipeline holder. Managed mode populates the
	// initial transforms from the control plane and starts a poller that
	// hot-reloads the pipeline.
	bodyLimits := transform.BodyLimits{
		MaxRequestBodyBytes:  cfg.Proxy.MaxRequestBodyBytes,
		MaxResponseBodyBytes: cfg.Proxy.MaxResponseBodyBytes,
	}

	// errc collects fatal errors from all background goroutines: servers
	// and (in managed mode) the config poller.
	errc := make(chan error, 5)

	// The postgres listener comes from the local YAML postgres: block
	// (self-managed proxies, inline DSNs) and, in managed mode, has additional
	// routes layered on from the control-plane sync payload. The manager is
	// created up front so the config poller can hot-reload it.
	localPgListener, err := postgres.LoadFromNode(cfg.Postgres, logger)
	if err != nil {
		logger.Error("loading postgres config", slog.String("error", err.Error()))
		os.Exit(1)
	}
	pgManager := postgres.NewManager(logger)
	pgListener := localPgListener

	var holder *transform.PipelineHolder
	var mcpHolder *mcp.PolicyHolder
	var gatewayHolder *mcpgateway.Holder
	var otelCfg iotel.ExportConfig
	var poller *controlplane.Poller

	if managed {
		var ingestToken string
		holder, mcpHolder, gatewayHolder, ingestToken, pgListener, poller = initManaged(ctx, cfg, bodyLimits, errc, proxyToken, pgManager, localPgListener, logger)
		if ingestToken != "" {
			otelCfg.DefaultEndpoint = "https://ingest.iron.sh/v1/logs"
			otelCfg.DefaultHeaders = map[string]string{
				"Authorization": "Bearer " + ingestToken,
			}
		}
	} else {
		holder, mcpHolder, gatewayHolder = initStandalone(cfg, bodyLimits, logger)
	}

	// 5. Validate the fully-assembled config.
	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Set up audit function.
	auditFunc := transform.AuditFunc(transform.NewAuditLogger(logger))
	var otelShutdown func(context.Context) error
	if otelCfg.Enabled() {
		otelProvider, otelErr := iotel.NewLoggerProvider(ctx, otelCfg)
		if otelErr != nil {
			logger.Error("initializing OTEL log provider", slog.String("error", otelErr.Error()))
			os.Exit(1)
		}
		otelShutdown = otelProvider.Shutdown
		auditFunc = transform.ChainAuditFuncs(auditFunc, transform.NewOTELAuditFunc(otelProvider))
		logger.Info("OTEL audit export enabled")
	}
	holder.Load().SetAuditFunc(auditFunc)

	// Initialize cert cache. Not needed in sni-only mode since TLS is never
	// terminated and no leaf certs are generated.
	var certCache *certcache.Cache
	if cfg.TLS.Mode != config.TLSModeSNIOnly {
		leafExpiry := time.Duration(cfg.TLS.LeafCertExpiryHours) * time.Hour
		certCache, err = certcache.New(cfg.TLS.CACert, cfg.TLS.CAKey, cfg.TLS.CertCacheSize, leafExpiry)
		if err != nil {
			logger.Error("initializing cert cache", slog.String("error", err.Error()))
			os.Exit(1)
		}
	} else if cfg.TLS.CACert != "" || cfg.TLS.CAKey != "" {
		logger.Warn("tls.ca_cert and tls.ca_key are ignored when tls.mode=sni-only")
	}

	// Build upstream resolver.
	resolver := net.DefaultResolver
	if cfg.DNS.UpstreamResolver != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", cfg.DNS.UpstreamResolver)
			},
		}
		logger.Info("using upstream resolver", slog.String("addr", cfg.DNS.UpstreamResolver))
	}

	// Initialize DNS server unless disabled. When off, clients are expected to
	// reach the proxy via explicit HTTP(S)_PROXY settings rather than DNS
	// interception.
	var dnsServer *idns.Server
	if cfg.DNS.IsEnabled() {
		dnsServer, err = idns.New(cfg.DNS, resolver, logger)
		if err != nil {
			logger.Error("initializing DNS server", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	// Build the upstream-dial deny guard. config.Validate has already
	// confirmed the entries parse, so this should not fail.
	guard, err := dnsguard.New(cfg.Proxy.UpstreamDenyCIDRs.Values)
	if err != nil {
		logger.Error("initializing upstream deny guard", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if len(cfg.Proxy.UpstreamDenyCIDRs.Values) > 0 {
		logger.Info("upstream deny list active",
			slog.Any("cidrs", cfg.Proxy.UpstreamDenyCIDRs.Values),
		)
	}

	responseRetryHandler, responseRetryStatuses, err := responseRetryHandlerFromEnv(
		os.Getenv,
		time.Duration(cfg.Proxy.UpstreamResponseHeaderTimeout),
		resolver,
		guard,
	)
	if err != nil {
		logger.Error("initializing response retry handler", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if responseRetryHandler != nil {
		logger.Info("response retry handler enabled", slog.Any("statuses", responseRetryStatuses))
	}

	// Initialize proxy.
	p := proxy.New(proxy.Options{
		HTTPAddr:                      cfg.Proxy.HTTPListen,
		HTTPSAddr:                     cfg.Proxy.HTTPSListen,
		TunnelAddr:                    cfg.Proxy.TunnelListen,
		TLSMode:                       cfg.TLS.Mode,
		CertCache:                     certCache,
		Pipeline:                      holder,
		Resolver:                      resolver,
		Guard:                         guard,
		MCPPolicy:                     mcpHolder,
		MCPGateway:                    gatewayHolder,
		ResponseRetryHandler:          responseRetryHandler,
		Logger:                        logger,
		UpstreamResponseHeaderTimeout: time.Duration(cfg.Proxy.UpstreamResponseHeaderTimeout),
		UpstreamProxy:                 cfg.Proxy.UpstreamProxy.ProxyFunc(),
		// Managed proxies fail closed until the first control-plane config
		// has been applied; an un-synced pipeline would otherwise pass
		// requests through with placeholder credentials intact.
		Ready: managedReady(poller),
	})

	// Initialize metrics server.
	metricsServer := metrics.New(cfg.Metrics.Listen, logger)

	// Initialize management server: /v1/reload in standalone mode,
	// /v1/status and /v1/sync in managed mode.
	var mgmtServer *management.Server
	if cfg.Management.Listen != "" {
		mgmtOpts := management.Options{
			Addr:   cfg.Management.Listen,
			APIKey: os.Getenv(cfg.Management.APIKeyEnv),
			Logger: logger,
			Ctx:    ctx,
		}
		if managed {
			mgmtOpts.Status = func() any { return poller.Status() }
			mgmtOpts.SyncNow = poller.Poke
		} else {
			mgmtOpts.Reload = newReloadFunc(*configPath, holder, mcpHolder, gatewayHolder, pgManager, bodyLimits, logger)
		}
		mgmtServer = management.New(mgmtOpts)
	}

	// Start services.
	if dnsServer != nil {
		go func() { errc <- fmt.Errorf("dns: %w", dnsServer.ListenAndServe()) }()
	}
	go func() { errc <- fmt.Errorf("proxy: %w", p.ListenAndServe()) }()
	go func() { errc <- fmt.Errorf("metrics: %w", metricsServer.ListenAndServe()) }()
	if mgmtServer != nil {
		go func() { errc <- fmt.Errorf("management: %w", mgmtServer.ListenAndServe()) }()
	}
	pgManager.Start(pgListener, errc)

	dnsListen := "disabled"
	if cfg.DNS.IsEnabled() {
		dnsListen = cfg.DNS.Listen
	}
	startAttrs := []any{
		slog.String("dns_listen", dnsListen),
		slog.String("http_listen", cfg.Proxy.HTTPListen),
		slog.String("https_listen", cfg.Proxy.HTTPSListen),
		slog.String("metrics_listen", cfg.Metrics.Listen),
	}
	if cfg.Proxy.TunnelListen != "" {
		startAttrs = append(startAttrs, slog.String("tunnel_listen", cfg.Proxy.TunnelListen))
	}
	logger.Info("iron-proxy starting", startAttrs...)
	if pipeline := holder.Load(); !pipeline.Empty() {
		logger.Info("transform pipeline", slog.String("transforms", pipeline.Names()))
	}

	// Wait for shutdown signal or fatal error from any background goroutine.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigc:
		logger.Info("received signal, shutting down", slog.String("signal", sig.String()))
	case err := <-errc:
		logger.Error("fatal error", slog.String("error", err.Error()))
	}

	// Cancel context to stop the poller, then shut down services.
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if otelShutdown != nil {
		if err := otelShutdown(shutdownCtx); err != nil {
			logger.Error("shutting down OTEL log provider", slog.String("error", err.Error()))
		}
	}
	if dnsServer != nil {
		if err := dnsServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("dns shutdown error", slog.String("error", err.Error()))
		}
	}
	if err := p.Shutdown(shutdownCtx); err != nil {
		logger.Error("proxy shutdown error", slog.String("error", err.Error()))
	}
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("metrics server shutdown error", slog.String("error", err.Error()))
	}
	if mgmtServer != nil {
		if err := mgmtServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("management server shutdown error", slog.String("error", err.Error()))
		}
	}
	if err := pgManager.Shutdown(shutdownCtx); err != nil {
		logger.Error("postgres server shutdown error", slog.String("error", err.Error()))
	}

	logger.Info("iron-proxy stopped")
}

// initManaged registers with the control plane, performs an initial sync, builds
// the initial pipeline and MCP policy, and starts the config poller. The poller
// runs until ctx is canceled and sends fatal errors on errc. Returns the
// pipeline holder, the MCP policy holder, and the ingest token from the initial
// sync (empty if the sync failed).
//
// Initial MCP policy preference: control-plane-supplied mcp block first, then
// fall back to cfg.MCP from the YAML if the sync did not include one.
func initManaged(ctx context.Context, cfg *config.Config, bodyLimits transform.BodyLimits, errc chan<- error, proxyToken string, pgManager *postgres.Manager, localPgListener *postgres.Listener, logger *slog.Logger) (*transform.PipelineHolder, *mcp.PolicyHolder, *mcpgateway.Holder, string, *postgres.Listener, *controlplane.Poller) {
	cpURL := envOrDefault("IRON_CONTROL_PLANE_URL", "https://api.iron.sh")
	logger.Info("starting in managed mode", slog.String("control_plane_url", cpURL))

	client := controlplane.NewClient(cpURL, proxyToken, logger)

	// Initial sync.
	syncResp, err := client.Sync(ctx, "")
	if err != nil {
		var apiErr *controlplane.APIError
		if errors.As(err, &apiErr) && apiErr.Code == controlplane.ErrProxyRevoked {
			logger.Error("proxy has been revoked, exiting")
			os.Exit(1)
		}
		logger.Warn("initial sync failed, will retry in background", slog.String("error", err.Error()))
	}

	configHash := ""
	ingestToken := ""
	var initialRules, initialSecrets, initialTransformsRaw, initialMCP, initialPostgres json.RawMessage
	if syncResp != nil {
		configHash = syncResp.ConfigHash
		initialRules = syncResp.Rules
		initialSecrets = syncResp.Secrets
		initialTransformsRaw = syncResp.Transforms
		initialMCP = syncResp.MCP
		initialPostgres = syncResp.Postgres
		ingestToken = syncResp.IngestToken
		if len(syncResp.Rules) > 0 || len(syncResp.Secrets) > 0 || len(syncResp.Transforms) > 0 || len(syncResp.MCP) > 0 {
			logger.Info("received initial config from control plane",
				slog.String("config_hash", syncResp.ConfigHash),
			)
		}
	}

	// Build initial pipeline from sync response.
	initialTransforms, err := config.TransformsFromSync(initialRules, initialSecrets, initialTransformsRaw)
	if err != nil {
		logger.Error("parsing initial config", slog.String("error", err.Error()))
		os.Exit(1)
	}

	pipeline, err := buildPipeline(initialTransforms, bodyLimits, logger)
	if err != nil {
		logger.Error("building initial pipeline", slog.String("error", err.Error()))
		os.Exit(1)
	}
	holder := transform.NewPipelineHolder(pipeline)

	// Build initial MCP policy: prefer the control-plane-supplied block; fall
	// back to cfg.MCP from the YAML so an operator can ship a default that
	// applies until the first sync arrives.
	mcpHolder, err := buildInitialMCPHolder(cfg, initialMCP, logger)
	if err != nil {
		logger.Error("building initial mcp policy", slog.String("error", err.Error()))
		os.Exit(1)
	}
	gateway, err := mcpgateway.LoadFromNode(cfg.MCPGateway)
	if err != nil {
		logger.Error("building initial mcp gateway", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if gateway != nil {
		logger.Info("mcp gateway enabled")
	}
	gatewayHolder := mcpgateway.NewHolder(gateway)

	// Compute the initial postgres listener: the local YAML listener with any
	// control-plane-synced routes layered on when its env vars are present. If
	// the initial sync carried no postgres block (or an invalid one), fall back
	// to the local listener.
	pgListener := localPgListener
	if listener, ok := postgresListenerFromSync(localPgListener, os.Getenv, logger, initialPostgres); ok {
		pgListener = listener
	}

	// Start config poller.
	poller := controlplane.NewPollerWithInterval(client, configHash, func(u controlplane.SyncUpdate) error {
		if u.Rules != nil || u.Secrets != nil || u.Transforms != nil {
			if err := applyPipelineSync(holder, bodyLimits, logger, u.Rules, u.Secrets, u.Transforms); err != nil {
				return err
			}
		}
		if u.MCP != nil {
			if err := applyMCPSync(mcpHolder, logger, u.MCP); err != nil {
				return err
			}
		}
		if u.Postgres != nil {
			if err := applyPostgresSync(ctx, pgManager, localPgListener, os.Getenv, logger, u.Postgres); err != nil {
				return err
			}
		}
		return nil
	}, logger, time.Duration(cfg.ControlPlane.PollInterval))

	// Seed the poller's status from the startup sync so /v1/status (and the
	// fail-closed gate) reflect it before the polling loop's first pass.
	poller.SeedStatus(syncResp)

	go func() {
		errc <- poller.Run(ctx)
	}()

	return holder, mcpHolder, gatewayHolder, ingestToken, pgListener, poller
}

// managedReady gates the proxy on the first applied control-plane config.
// A nil poller (standalone mode) means always ready.
func managedReady(poller *controlplane.Poller) func() bool {
	if poller == nil {
		return nil
	}
	return func() bool { return poller.Status().SyncedOnce }
}

// buildInitialMCPHolder picks the initial MCP policy source: a control-plane
// MCP block when present, otherwise the YAML cfg.MCP fallback. A nil holder
// means "no policy configured"; the proxy treats it as MCP disabled.
func buildInitialMCPHolder(cfg *config.Config, initialMCP json.RawMessage, logger *slog.Logger) (*mcp.PolicyHolder, error) {
	node, present, err := config.MCPFromSync(initialMCP)
	if err != nil {
		return nil, err
	}
	if !present {
		node = cfg.MCP
	}
	policy, err := mcp.LoadFromNode(node)
	if err != nil {
		return nil, err
	}
	if policy != nil {
		logger.Info("mcp policy enabled")
	}
	return mcp.NewPolicyHolder(policy), nil
}

// initStandalone builds the pipeline and MCP policy from the YAML config.
func initStandalone(cfg *config.Config, bodyLimits transform.BodyLimits, logger *slog.Logger) (*transform.PipelineHolder, *mcp.PolicyHolder, *mcpgateway.Holder) {
	pipeline, err := buildPipeline(cfg.Transforms, bodyLimits, logger)
	if err != nil {
		logger.Error("building transform pipeline", slog.String("error", err.Error()))
		os.Exit(1)
	}
	mcpPolicy, err := mcp.LoadFromNode(cfg.MCP)
	if err != nil {
		logger.Error("loading mcp policy", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if mcpPolicy != nil {
		logger.Info("mcp policy enabled")
	}
	gateway, err := mcpgateway.LoadFromNode(cfg.MCPGateway)
	if err != nil {
		logger.Error("loading mcp gateway", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if gateway != nil {
		logger.Info("mcp gateway enabled")
	}
	return transform.NewPipelineHolder(pipeline), mcp.NewPolicyHolder(mcpPolicy), mcpgateway.NewHolder(gateway)
}

// applyPipelineSync builds a new pipeline from a sync payload and atomically
// swaps it in. If parsing or pipeline construction fails, the existing pipeline
// is preserved and an error is logged: an invalid push from the control plane
// must not take down the proxy.
func applyPipelineSync(holder *transform.PipelineHolder, bodyLimits transform.BodyLimits, logger *slog.Logger, rules, secrets, transforms json.RawMessage) error {
	newTransforms, err := config.TransformsFromSync(rules, secrets, transforms)
	if err != nil {
		logger.Error("rejecting invalid pipeline config from sync, keeping current pipeline", slog.String("error", err.Error()))
		return fmt.Errorf("pipeline sync: %w", err)
	}
	newPipeline, err := buildPipeline(newTransforms, bodyLimits, logger)
	if err != nil {
		logger.Error("rejecting invalid pipeline config from sync, keeping current pipeline", slog.String("error", err.Error()))
		return fmt.Errorf("pipeline sync: %w", err)
	}
	newPipeline.SetAuditFunc(holder.Load().AuditFunc())
	holder.Store(newPipeline)
	logger.Info("pipeline reloaded", slog.String("transforms", newPipeline.Names()))
	return nil
}

// applyMCPSync compiles a new MCP policy from a sync payload and atomically
// swaps it in. Parse or compile errors are logged and the prior policy is
// preserved: an invalid push from the control plane must not take down a
// running proxy. An empty/null mcp block is interpreted by the caller as
// "no update" and is not delivered here.
func applyMCPSync(holder *mcp.PolicyHolder, logger *slog.Logger, raw json.RawMessage) error {
	node, present, err := config.MCPFromSync(raw)
	if err != nil {
		logger.Error("rejecting invalid mcp policy from sync, keeping current policy", slog.String("error", err.Error()))
		return fmt.Errorf("mcp sync: %w", err)
	}
	if !present {
		// Should not happen — caller filters absent/null — but treat as no-op.
		return nil
	}
	policy, err := mcp.LoadFromNode(node)
	if err != nil {
		logger.Error("rejecting invalid mcp policy from sync, keeping current policy", slog.String("error", err.Error()))
		return fmt.Errorf("mcp sync: %w", err)
	}
	holder.Store(policy)
	if policy == nil {
		logger.Info("mcp policy cleared by control plane")
	} else {
		logger.Info("mcp policy reloaded")
	}
	return nil
}

// Environment variables that configure the managed postgres listener when the
// proxy has no local YAML postgres block to source these from. They configure
// the single listener, not individual upstreams.
const (
	pgListenEnv         = "IRON_PROXY_PG_LISTEN"
	pgClientUserEnv     = "IRON_PROXY_PG_CLIENT_USER"
	pgClientPasswordEnv = "IRON_PROXY_PG_CLIENT_PASSWORD"
)

// postgresListenerFromSync builds the single postgres listener for managed mode.
// Each synced entry becomes an upstream keyed by its database, carrying the
// database, DSN, and role the control plane delivered.
//
// When a local YAML postgres block is present, the synced upstreams are layered
// onto it, reusing its bind address and client credential; a synced upstream
// whose database collides with a local one is dropped (logged). Otherwise the
// listener is built from the environment: IRON_PROXY_PG_LISTEN plus the shared
// IRON_PROXY_PG_CLIENT_USER / IRON_PROXY_PG_CLIENT_PASSWORD. When no bind address
// or client credential is available, or no upstreams resolve, no listener is
// returned. Returns ok=false only when the sync payload itself is invalid,
// signaling the caller to keep the current listener.
func postgresListenerFromSync(local *postgres.Listener, getenv func(string) string, logger *slog.Logger, raw json.RawMessage) (*postgres.Listener, bool) {
	entries, err := config.PostgresFromSync(raw, logger)
	if err != nil {
		logger.Error("rejecting invalid postgres config from sync, keeping current listener", slog.String("error", err.Error()))
		return nil, false
	}

	synced := make([]*postgres.Upstream, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		u, err := postgres.NewManagedUpstream(e.Database, e.DSN, e.Role, e.Settings)
		if err != nil {
			logger.Error("skipping synced postgres upstream: invalid upstream",
				slog.String("foreign_id", e.ForeignID),
				slog.String("error", err.Error()),
			)
			continue
		}
		if seen[u.Database()] {
			logger.Warn("skipping synced postgres upstream: duplicate database",
				slog.String("foreign_id", e.ForeignID),
				slog.String("database", u.Database()),
			)
			continue
		}
		seen[u.Database()] = true
		synced = append(synced, u)
	}

	// With a local listener, layer the synced upstreams on top, reusing its
	// address and client credential. Local wins on a database collision.
	if local != nil {
		merged, dropped := local.WithUpstreams(synced)
		for _, db := range dropped {
			logger.Warn("skipping synced postgres upstream: duplicate database",
				slog.String("database", db))
		}
		return merged, true
	}

	// No local listener: source the listener knobs from the environment.
	if len(synced) == 0 {
		return nil, true
	}
	listen := getenv(pgListenEnv)
	clientUser := getenv(pgClientUserEnv)
	clientPassword := getenv(pgClientPasswordEnv)
	if listen == "" || clientUser == "" || clientPassword == "" {
		logger.Info("skipping control-plane postgres upstreams: listener env not fully set",
			slog.Bool("has_listen", listen != ""),
			slog.Bool("has_client_user", clientUser != ""),
			slog.Bool("has_client_password", clientPassword != ""),
			slog.Int("upstream_count", len(synced)),
		)
		return nil, true
	}

	listener, err := postgres.NewListener(listen, clientUser, clientPassword, synced)
	if err != nil {
		logger.Error("skipping postgres listener: invalid listener", slog.String("error", err.Error()))
		return nil, true
	}
	return listener, true
}

// applyPostgresSync rebuilds the postgres listener from a sync payload and
// hot-reloads the manager. An invalid payload is logged and the running
// listener is preserved.
func applyPostgresSync(ctx context.Context, mgr *postgres.Manager, local *postgres.Listener, getenv func(string) string, logger *slog.Logger, raw json.RawMessage) error {
	listener, ok := postgresListenerFromSync(local, getenv, logger, raw)
	if !ok {
		return fmt.Errorf("postgres sync: invalid postgres config")
	}
	mgr.Reload(ctx, listener)
	logger.Info("postgres listener reloaded from sync", slog.Bool("running", listener != nil))
	return nil
}

// newReloadFunc returns a management.ReloadFunc that re-reads the YAML config
// from configPath, rebuilds the pipeline, MCP policy, and postgres listeners,
// and atomically swaps them in. Parse, validation, and build errors are
// wrapped in *management.ValidationError so the management server returns
// 422 and the existing state is left untouched. Validation runs for every
// component before any state is mutated.
func newReloadFunc(configPath string, holder *transform.PipelineHolder, mcpHolder *mcp.PolicyHolder, gatewayHolder *mcpgateway.Holder, pgManager *postgres.Manager, bodyLimits transform.BodyLimits, logger *slog.Logger) management.ReloadFunc {
	return func(ctx context.Context) error {
		newCfg, err := config.LoadConfig(configPath)
		if err != nil {
			return &management.ValidationError{Err: err}
		}
		if err := config.Validate(newCfg); err != nil {
			return &management.ValidationError{Err: err}
		}
		newPipeline, err := buildPipeline(newCfg.Transforms, bodyLimits, logger)
		if err != nil {
			return &management.ValidationError{Err: err}
		}
		newPolicy, err := mcp.LoadFromNode(newCfg.MCP)
		if err != nil {
			return &management.ValidationError{Err: err}
		}
		newGateway, err := mcpgateway.LoadFromNode(newCfg.MCPGateway)
		if err != nil {
			return &management.ValidationError{Err: err}
		}
		newPgListener, err := postgres.LoadFromNode(newCfg.Postgres, logger)
		if err != nil {
			return &management.ValidationError{Err: err}
		}
		newPipeline.SetAuditFunc(holder.Load().AuditFunc())
		holder.Store(newPipeline)
		mcpHolder.Store(newPolicy)
		gatewayHolder.Store(newGateway)
		pgManager.Reload(ctx, newPgListener)
		logger.Info("pipeline reloaded via management API",
			slog.String("transforms", newPipeline.Names()),
			slog.Bool("postgres_listener", newPgListener != nil),
		)
		return nil
	}
}

// buildPipeline creates a transform.Pipeline from config transforms.
func buildPipeline(transforms []config.Transform, bodyLimits transform.BodyLimits, logger *slog.Logger) (*transform.Pipeline, error) {
	var transformers []transform.Transformer
	for _, tc := range transforms {
		factory, err := transform.Lookup(tc.Name)
		if err != nil {
			return nil, fmt.Errorf("unknown transform %q: %w", tc.Name, err)
		}
		t, err := factory(tc.Config, logger)
		if err != nil {
			return nil, fmt.Errorf("initializing transform %q: %w", tc.Name, err)
		}
		transformers = append(transformers, t)
	}
	return transform.NewPipeline(transformers, bodyLimits, logger), nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseResponseRetryStatuses(value string) ([]int, error) {
	var statuses []int
	for _, part := range splitCommaSeparated(value) {
		status, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid status %q", part)
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func responseRetryHandlerFromEnv(getenv func(string) string, timeout time.Duration, resolver *net.Resolver, guard *dnsguard.Guard) (*responseretry.Handler, []int, error) {
	handlerURL := getenv("IRON_RESPONSE_RETRY_HANDLER_URL")
	if handlerURL == "" {
		return nil, nil, nil
	}
	allowHTTPValue := getenv("IRON_RESPONSE_RETRY_HANDLER_ALLOW_HTTP")
	if allowHTTPValue == "" {
		allowHTTPValue = "false"
	}
	allowHTTP, err := strconv.ParseBool(allowHTTPValue)
	if err != nil {
		return nil, nil, fmt.Errorf("parse HTTP allowance: %w", err)
	}
	statuses, err := parseResponseRetryStatuses(getenv("IRON_RESPONSE_RETRY_STATUSES"))
	if err != nil {
		return nil, nil, fmt.Errorf("parse statuses: %w", err)
	}
	completionHeaders := getenv("IRON_RESPONSE_RETRY_COMPLETION_HEADERS")
	if completionHeaders == "" {
		completionHeaders = "Payment-Receipt"
	}
	handler, err := responseretry.New(responseretry.Options{
		AuthorizeEndpoint: handlerURL,
		CompleteEndpoint:  getenv("IRON_RESPONSE_RETRY_COMPLETE_URL"),
		Token:             getenv("IRON_RESPONSE_RETRY_HANDLER_TOKEN"),
		SandboxID:         getenv("IRON_RESPONSE_RETRY_HANDLER_SANDBOX_ID"),
		Statuses:          statuses,
		AllowHTTP:         allowHTTP,
		CompletionHeaders: splitCommaSeparated(completionHeaders),
		AllowCIDRs:        splitCommaSeparated(getenv("IRON_RESPONSE_RETRY_HANDLER_ALLOW_CIDRS")),
		Resolver:          resolver,
		Guard:             guard,
		ClientTimeout:     timeout,
	})
	if err != nil {
		return nil, nil, err
	}
	return handler, statuses, nil
}

func splitCommaSeparated(value string) []string {
	var values []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			values = append(values, part)
		}
	}
	return values
}
