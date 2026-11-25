package awsauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

type credentialsProviderBuilder func(yaml.Node, *slog.Logger) (aws.CredentialsProvider, error)

type providerTypeHint struct {
	Type string `yaml:"type"`
}

// BuildCredentialsProvider dispatches a credentials_provider node through the
// default registry. Mirrors secrets.BuildSource.
func BuildCredentialsProvider(node yaml.Node, logger *slog.Logger) (aws.CredentialsProvider, error) {
	var hint providerTypeHint
	if err := node.Decode(&hint); err != nil {
		return nil, fmt.Errorf("parsing credentials_provider type: %w", err)
	}
	if hint.Type == "" {
		return nil, fmt.Errorf("credentials_provider.type is required")
	}
	builder, ok := defaultCredentialsProviderRegistry()[hint.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported credentials_provider type %q", hint.Type)
	}
	return builder(node, logger)
}

func defaultCredentialsProviderRegistry() map[string]credentialsProviderBuilder {
	return map[string]credentialsProviderBuilder{
		providerWorkloadIdentity: buildWorkloadIdentity,
	}
}

type workloadIdentityConfig struct {
	Type   string `yaml:"type"`
	Region string `yaml:"region,omitempty"`
}

// buildWorkloadIdentity returns a provider that defers to the AWS SDK default
// credential chain (IRSA, EKS Pod Identity, IMDSv2, env, profiles, SSO). The
// SDK config load is deferred to the first Retrieve so factory-time validation
// does not require a reachable metadata server.
func buildWorkloadIdentity(node yaml.Node, _ *slog.Logger) (aws.CredentialsProvider, error) {
	var cfg workloadIdentityConfig
	if err := node.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing workload_identity provider: %w", err)
	}
	if cfg.Region != "" {
		if err := transform.ValidateAWSRegion(cfg.Region); err != nil {
			return nil, fmt.Errorf("credentials_provider region: %w", err)
		}
	}
	return aws.NewCredentialsCache(&lazyDefaultChainProvider{region: cfg.Region}), nil
}

// lazyDefaultChainProvider loads awsconfig.LoadDefaultConfig on first Retrieve.
// The inner provider tracks its own expiry; aws.NewCredentialsCache wraps this
// at the call site to normalize refresh.
type lazyDefaultChainProvider struct {
	region string

	mu    sync.Mutex
	inner aws.CredentialsProvider
}

func (p *lazyDefaultChainProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	p.mu.Lock()
	if p.inner == nil {
		var opts []func(*awsconfig.LoadOptions) error
		if p.region != "" {
			opts = append(opts, awsconfig.WithRegion(p.region))
		}
		if dial := transform.OutboundDialer(); dial != nil {
			client := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
				tr.DialContext = dial
				// An env proxy would hide the real destination from the guard.
				tr.Proxy = nil
			})
			opts = append(opts, awsconfig.WithHTTPClient(client))
		}
		cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			p.mu.Unlock()
			return aws.Credentials{}, fmt.Errorf("loading AWS default credential chain: %w", err)
		}
		if cfg.Credentials == nil {
			p.mu.Unlock()
			return aws.Credentials{}, fmt.Errorf("AWS default credential chain returned no credentials provider")
		}
		p.inner = cfg.Credentials
	}
	inner := p.inner
	p.mu.Unlock()
	return inner.Retrieve(ctx)
}
