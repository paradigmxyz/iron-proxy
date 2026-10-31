// Package awsauth implements an AWS Signature Version 4 request-signing
// transform. The inbound request is expected to already carry a SigV4
// signature produced by any AWS SDK using placeholder credentials. This
// transform reads the region and service from the inbound credential scope,
// strips the placeholder signature, and re-signs the request with real
// credentials. This lets a single transform entry handle every AWS service a
// client speaks to without enumerating them in config.
//
// Credentials come from one of two sources, mutually exclusive:
//   - access_key_id + secret_access_key: each backed by any registered secret
//     source (env, aws_sm, aws_ssm, 1password, ...). Best for calling AWS
//     from outside AWS with long-lived static keys.
//   - credentials_provider: a structured block dispatching on a type field.
//     The "workload_identity" type defers to the AWS SDK default credential
//     chain, which natively resolves IRSA, EKS Pod Identity, IMDSv2, env
//     vars, shared profiles, and SSO. Best for pod-bound rotating creds the
//     agent should never see.
//
// Like hmac_sign, this requires MITM mode: sni-only mode has no method, path,
// or body to sign. A truncated body would produce an invalid signature, so
// bodies shorter than Content-Length and chunked bodies are rejected by
// default; set allow_chunked_body: true to opt out of the chunked check, or
// unsigned_payload: true to sign without buffering the body at all (S3
// streaming uploads, etc.).
package awsauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

func init() {
	transform.Register("aws_auth", factory)
}

const (
	// unsignedPayload is the literal placeholder AWS accepts in lieu of a real
	// SHA-256 payload hash. S3, Bedrock streaming, etc. document this value.
	unsignedPayload = "UNSIGNED-PAYLOAD"

	// emptyPayloadSHA256 is the hex SHA-256 of the empty string, used when the
	// request has no body. Per the SDK docs SignHTTP always requires a payload
	// hash, even for empty bodies.
	emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	sigV4Algorithm = "AWS4-HMAC-SHA256"
)

type config struct {
	AccessKeyID         yaml.Node              `yaml:"access_key_id,omitempty"`
	SecretAccessKey     yaml.Node              `yaml:"secret_access_key,omitempty"`
	CredentialsProvider yaml.Node              `yaml:"credentials_provider,omitempty"`
	AllowedRegions      []string               `yaml:"allowed_regions,omitempty"`
	AllowedServices     []string               `yaml:"allowed_services,omitempty"`
	UnsignedPayload     bool                   `yaml:"unsigned_payload,omitempty"`
	AllowChunkedBody    bool                   `yaml:"allow_chunked_body,omitempty"`
	Rules               []hostmatch.RuleConfig `yaml:"rules"`
}

// sourceBuilder is the signature of secrets.BuildSource, factored out so tests
// can substitute a stub builder.
type sourceBuilder func(yaml.Node, *slog.Logger) (secrets.Source, error)

// signFunc is the part of the AWS SDK v4 signer the transform uses. Factored
// into a function value so tests can inject deterministic behavior without
// reaching for the real signer.
type signFunc func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error

// Credential provider kinds, annotated on credential-unavailable rejections.
const (
	providerStatic           = "static"
	providerWorkloadIdentity = "workload_identity"
)

// AWSAuth is the transform.
type AWSAuth struct {
	logger           *slog.Logger
	rules            []hostmatch.Rule
	allowedRegions   map[string]struct{} // nil → allow any
	allowedServices  map[string]struct{} // nil → allow any
	creds            aws.CredentialsProvider
	unsignedPayload  bool
	allowChunkedBody bool

	now  func() time.Time
	sign signFunc
}

// credsKind reports which kind of provider backs the transform, for telemetry.
func (a *AWSAuth) credsKind() string {
	if _, ok := a.creds.(*staticSourceProvider); ok {
		return providerStatic
	}
	return providerWorkloadIdentity
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing aws_auth config: %w", err)
	}
	return newFromConfig(c, logger, secrets.BuildSource, BuildCredentialsProvider)
}

func newFromConfig(c config, logger *slog.Logger, build sourceBuilder, buildCreds credentialsProviderBuilder) (*AWSAuth, error) {
	hasStatic := !c.AccessKeyID.IsZero() || !c.SecretAccessKey.IsZero()
	hasProvider := !c.CredentialsProvider.IsZero()
	if hasStatic && hasProvider {
		return nil, fmt.Errorf("aws_auth: set either access_key_id/secret_access_key or credentials_provider, not both")
	}
	if !hasStatic && !hasProvider {
		return nil, fmt.Errorf("aws_auth: requires either access_key_id+secret_access_key or credentials_provider")
	}

	var creds aws.CredentialsProvider
	if hasProvider {
		p, err := buildCreds(c.CredentialsProvider, logger)
		if err != nil {
			return nil, fmt.Errorf("aws_auth: building credentials_provider: %w", err)
		}
		creds = p
	} else {
		if c.AccessKeyID.IsZero() {
			return nil, fmt.Errorf("aws_auth: access_key_id is required")
		}
		if c.SecretAccessKey.IsZero() {
			return nil, fmt.Errorf("aws_auth: secret_access_key is required")
		}
		accessKey, err := build(c.AccessKeyID, logger)
		if err != nil {
			return nil, fmt.Errorf("aws_auth: building access_key_id source: %w", err)
		}
		secretKey, err := build(c.SecretAccessKey, logger)
		if err != nil {
			return nil, fmt.Errorf("aws_auth: building secret_access_key source: %w", err)
		}
		creds = &staticSourceProvider{accessKey: accessKey, secretKey: secretKey}
	}

	rules, err := hostmatch.CompileRules(c.Rules, "aws_auth")
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("aws_auth: at least one entry in \"rules\" is required")
	}

	signer := v4.NewSigner()
	return &AWSAuth{
		logger:           logger,
		rules:            rules,
		allowedRegions:   buildAllowSet(c.AllowedRegions),
		allowedServices:  buildAllowSet(c.AllowedServices),
		creds:            creds,
		unsignedPayload:  c.UnsignedPayload,
		allowChunkedBody: c.AllowChunkedBody,
		now:              time.Now,
		sign: func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error {
			return signer.SignHTTP(ctx, creds, req, payloadHash, service, region, signingTime, func(o *v4.SignerOptions) {
				o.DisableURIPathEscaping = service == "s3"
			})
		},
	}, nil
}

// staticSourceProvider adapts two secrets.Source values into an
// aws.CredentialsProvider. The sources do their own TTL caching.
type staticSourceProvider struct {
	accessKey secrets.Source
	secretKey secrets.Source
}

func (p *staticSourceProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	ak, err := p.accessKey.Get(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("access_key_id: %w", err)
	}
	sk, err := p.secretKey.Get(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("secret_access_key: %w", err)
	}
	return aws.Credentials{
		AccessKeyID:     ak,
		SecretAccessKey: sk,
		Source:          "iron-proxy aws_auth static",
	}, nil
}

func buildAllowSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(items))
	for _, v := range items {
		if v == "" {
			continue
		}
		out[v] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (a *AWSAuth) Name() string { return "aws_auth" }

func (a *AWSAuth) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	// The proxy replays request transforms against a synthetic CONNECT request
	// to make tunnel-level policy decisions before MITM (see proxy.tunnelTransformCheck).
	// A CONNECT carries no SigV4 signature — the signed request only becomes
	// visible after the tunnel is established and TLS is terminated. Rejecting
	// it here would kill the tunnel before the real request is ever seen, so let
	// CONNECT pass; signing happens on the post-MITM request that follows.
	if req.Method == http.MethodConnect {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	if !hostmatch.MatchAnyRule(a.rules, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	scope, err := parseInboundScope(req)
	if err != nil {
		tctx.Annotate("rejected", "missing_sigv4")
		tctx.Annotate("error", err.Error())
		return &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusBadRequest, "missing_sigv4"),
		}, nil
	}

	if a.allowedRegions != nil {
		if _, ok := a.allowedRegions[scope.region]; !ok {
			tctx.Annotate("rejected", "region_not_allowed")
			tctx.Annotate("region", scope.region)
			return &transform.TransformResult{
				Action:   transform.ActionReject,
				Response: errorResponse(req, http.StatusForbidden, "region_not_allowed"),
			}, nil
		}
	}
	if a.allowedServices != nil {
		if _, ok := a.allowedServices[scope.service]; !ok {
			tctx.Annotate("rejected", "service_not_allowed")
			tctx.Annotate("service", scope.service)
			return &transform.TransformResult{
				Action:   transform.ActionReject,
				Response: errorResponse(req, http.StatusForbidden, "service_not_allowed"),
			}, nil
		}
	}

	creds, err := a.creds.Retrieve(ctx)
	if err != nil {
		return a.rejectCredentialUnavailable(tctx, req, a.credsKind(), err), nil
	}

	payloadHash, reject := a.payloadHash(tctx, req)
	if reject != nil {
		return reject, nil
	}

	// Strip the inbound placeholder signature so SignHTTP produces a fresh,
	// untainted signature using only the headers we want signed.
	stripInboundSignatureHeaders(req)
	// X-Amz-Content-Sha256 is required by S3 and signed when present; setting
	// it explicitly makes the signed canonical request deterministic across
	// services.
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	if err := a.sign(ctx, creds, req, payloadHash, scope.service, scope.region, a.now()); err != nil {
		tctx.Annotate("rejected", "signing_failed")
		tctx.Annotate("error", err.Error())
		return &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusInternalServerError, "signing_failed"),
		}, nil
	}

	injected := []string{"header:Authorization", "header:X-Amz-Date", "header:X-Amz-Content-Sha256"}
	if creds.SessionToken != "" {
		injected = append(injected, "header:X-Amz-Security-Token")
	}
	tctx.Annotate("injected", injected)
	tctx.Annotate("service", scope.service)
	tctx.Annotate("region", scope.region)
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (a *AWSAuth) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// credentialScope is the (region, service) pair extracted from an inbound
// SigV4 signature.
type credentialScope struct {
	region  string
	service string
}

var errNoSigV4 = errors.New("request has no SigV4 signature (no Authorization header or X-Amz-Credential query param)")

// parseInboundScope extracts the credential scope from an inbound SigV4
// signature. Normal requests carry the scope in the Authorization header;
// pre-signed URLs carry it in the X-Amz-Credential query param.
func parseInboundScope(req *http.Request) (credentialScope, error) {
	if auth := req.Header.Get("Authorization"); auth != "" {
		return parseAuthHeaderScope(auth)
	}
	if cred := req.URL.Query().Get("X-Amz-Credential"); cred != "" {
		return parseCredentialPath(cred)
	}
	return credentialScope{}, errNoSigV4
}

// parseAuthHeaderScope pulls the Credential= field out of a SigV4
// Authorization header.
func parseAuthHeaderScope(auth string) (credentialScope, error) {
	rest, ok := strings.CutPrefix(auth, sigV4Algorithm+" ")
	if !ok {
		return credentialScope{}, fmt.Errorf("not a %s Authorization header", sigV4Algorithm)
	}
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		if cred, ok := strings.CutPrefix(part, "Credential="); ok {
			return parseCredentialPath(cred)
		}
	}
	return credentialScope{}, errors.New("missing Credential field in Authorization header")
}

// parseCredentialPath parses ACCESSKEY/DATE/REGION/SERVICE/aws4_request.
func parseCredentialPath(cred string) (credentialScope, error) {
	parts := strings.Split(cred, "/")
	if len(parts) != 5 {
		return credentialScope{}, fmt.Errorf("malformed credential scope %q: expected 5 path segments, got %d", cred, len(parts))
	}
	if parts[4] != "aws4_request" {
		return credentialScope{}, fmt.Errorf("malformed credential scope %q: expected aws4_request terminator", cred)
	}
	if parts[2] == "" || parts[3] == "" {
		return credentialScope{}, fmt.Errorf("malformed credential scope %q: empty region or service", cred)
	}
	return credentialScope{region: parts[2], service: parts[3]}, nil
}

// stripInboundSignatureHeaders removes every header SignHTTP is going to
// rewrite. Leaving the placeholder Authorization header in place would cause
// the SDK signer to include it in the canonical request, which produces a
// signature the upstream cannot verify.
func stripInboundSignatureHeaders(req *http.Request) {
	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Date")
	req.Header.Del("X-Amz-Security-Token")
	req.Header.Del("X-Amz-Content-Sha256")
}

// payloadHash returns the SHA-256 hex hash of the request body, or the
// UNSIGNED-PAYLOAD sentinel when unsigned_payload is set. It reuses
// hmac_sign's body-verification policy: a truncated body or (by default) a
// chunked body produces a clean proxy-side rejection rather than a request
// the upstream will reject with an opaque "signature mismatch" error.
func (a *AWSAuth) payloadHash(tctx *transform.TransformContext, req *http.Request) (string, *transform.TransformResult) {
	if a.unsignedPayload {
		return unsignedPayload, nil
	}

	if req.Body == nil || req.Body == http.NoBody {
		if req.ContentLength > 0 {
			tctx.Annotate("rejected", "body_missing")
			tctx.Annotate("content_length", req.ContentLength)
			return "", &transform.TransformResult{
				Action:   transform.ActionReject,
				Response: errorResponse(req, http.StatusBadRequest, "body_missing"),
			}
		}
		return emptyPayloadSHA256, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		tctx.Annotate("rejected", "body_read_failed")
		tctx.Annotate("error", err.Error())
		return "", &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusBadRequest, "body_read_failed"),
		}
	}

	switch {
	case req.ContentLength >= 0 && int64(len(body)) < req.ContentLength:
		tctx.Annotate("rejected", "body_truncated")
		tctx.Annotate("content_length", req.ContentLength)
		tctx.Annotate("buffered_length", len(body))
		return "", &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusRequestEntityTooLarge, "body_truncated"),
		}
	case req.ContentLength < 0 && !a.allowChunkedBody:
		tctx.Annotate("rejected", "chunked_body_not_allowed")
		return "", &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusBadRequest, "chunked_body_not_allowed"),
		}
	case req.ContentLength < 0 && a.allowChunkedBody:
		a.logger.Warn("aws_auth signing chunked request body without length verification",
			"host", hostmatch.StripPort(req.Host),
			"path", req.URL.Path,
			"buffered_length", len(body),
		)
	}

	req.Body = transform.NewBufferedBodyFromBytes(body)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func (a *AWSAuth) rejectCredentialUnavailable(tctx *transform.TransformContext, req *http.Request, which string, err error) *transform.TransformResult {
	tctx.Annotate("rejected", "credential_unavailable")
	tctx.Annotate("credential", which)
	tctx.Annotate("error", err.Error())
	return &transform.TransformResult{
		Action:   transform.ActionReject,
		Response: errorResponse(req, http.StatusBadGateway, "credential_unavailable"),
	}
}

func errorResponse(req *http.Request, status int, reason string) *http.Response {
	body := []byte(`{"error":"aws_auth","reason":"` + reason + `"}`)
	return &http.Response{
		StatusCode:    status,
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          transform.NewBufferedBodyFromBytes(body),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
