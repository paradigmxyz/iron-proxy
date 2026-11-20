package awsauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

type staticSource struct {
	name  string
	value string
	err   error
	calls atomic.Int64
}

func (s *staticSource) Name() string { return s.name }
func (s *staticSource) Get(context.Context) (string, error) {
	s.calls.Add(1)
	return s.value, s.err
}

// mapBuilder dispatches each credential node to a source keyed by the node's
// "var" field. The integration test config writes env-shaped sources so we can
// reuse the same shape.
func mapBuilder(srcs map[string]secrets.Source) sourceBuilder {
	return func(n yaml.Node, _ *slog.Logger) (secrets.Source, error) {
		var c struct {
			Var string `yaml:"var"`
		}
		if err := n.Decode(&c); err != nil {
			return nil, err
		}
		src, ok := srcs[c.Var]
		if !ok {
			return nil, fmt.Errorf("no test source for var %q", c.Var)
		}
		return src, nil
	}
}

func yamlFromString(t *testing.T, src string) yaml.Node {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &node))
	return *node.Content[0]
}

func newContext() *transform.TransformContext {
	return &transform.TransformContext{Mode: transform.ModeMITM, Logger: slog.Default()}
}

// signedRequest builds a request and pre-signs it with placeholder credentials
// for (region, service), mimicking what an AWS SDK would emit. The transform
// is expected to strip this placeholder signature and re-sign.
func signedRequest(t *testing.T, method, rawURL, region, service string, body []byte, maxBytes int64) *http.Request {
	t.Helper()
	var bodyReader io.Reader = http.NoBody
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, bodyReader)
	require.NoError(t, err)
	if body == nil {
		req.Body = transform.NewBufferedBody(http.NoBody, maxBytes)
	} else {
		req.Body = transform.NewBufferedBody(io.NopCloser(bytes.NewReader(body)), maxBytes)
		req.ContentLength = int64(len(body))
	}

	hash := emptyPayloadSHA256
	if len(body) > 0 {
		hash = sha256Hex(body)
	}
	signer := v4.NewSigner()
	creds := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	require.NoError(t, signer.SignHTTP(context.Background(), creds, req, hash, service, region, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)))
	return req
}

func buildTransformWith(t *testing.T, cfgYAML string, build sourceBuilder) *AWSAuth {
	t.Helper()
	return buildTransformWithBoth(t, cfgYAML, build, errCredBuilder)
}

func buildTransformWithBoth(t *testing.T, cfgYAML string, build sourceBuilder, buildCreds credentialsProviderBuilder) *AWSAuth {
	t.Helper()
	var c config
	node := yamlFromString(t, cfgYAML)
	require.NoError(t, node.Decode(&c))
	a, err := newFromConfig(c, slog.Default(), build, buildCreds)
	require.NoError(t, err)
	return a
}

// errCredBuilder fails if invoked. Used in tests that exercise the legacy
// static path so an accidental credentials_provider entry is caught.
func errCredBuilder(yaml.Node, *slog.Logger) (aws.CredentialsProvider, error) {
	return nil, fmt.Errorf("credentials_provider builder must not be called in this test")
}

// stubCredsProvider returns canned credentials.
type stubCredsProvider struct {
	creds aws.Credentials
	err   error
	calls atomic.Int64
}

func (p *stubCredsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	p.calls.Add(1)
	return p.creds, p.err
}

func stubCredBuilder(p aws.CredentialsProvider) credentialsProviderBuilder {
	return func(yaml.Node, *slog.Logger) (aws.CredentialsProvider, error) { return p, nil }
}

const minimalYAML = `
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
rules:
  - host: "*.amazonaws.com"
`

func TestNewFromConfig(t *testing.T) {
	srcs := map[string]secrets.Source{
		"AWS_ACCESS_KEY_ID":     &staticSource{name: "access", value: "AKIA"},
		"AWS_SECRET_ACCESS_KEY": &staticSource{name: "secret", value: "shh"},
	}

	t.Run("missing access key", func(t *testing.T) {
		var c config
		node := yamlFromString(t, `
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
rules:
  - host: "*.amazonaws.com"
`)
		require.NoError(t, node.Decode(&c))
		_, err := newFromConfig(c, slog.Default(), mapBuilder(srcs), errCredBuilder)
		require.ErrorContains(t, err, "access_key_id is required")
	})

	t.Run("missing rules", func(t *testing.T) {
		var c config
		node := yamlFromString(t, `
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
`)
		require.NoError(t, node.Decode(&c))
		_, err := newFromConfig(c, slog.Default(), mapBuilder(srcs), errCredBuilder)
		require.ErrorContains(t, err, `at least one entry in "rules" is required`)
	})

	t.Run("valid minimal config", func(t *testing.T) {
		a := buildTransformWith(t, minimalYAML, mapBuilder(srcs))
		require.Equal(t, "static", a.credsKind())
		require.Nil(t, a.allowedRegions)
		require.Nil(t, a.allowedServices)
	})

	t.Run("rejects both static and credentials_provider", func(t *testing.T) {
		var c config
		node := yamlFromString(t, `
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
credentials_provider:
  type: workload_identity
rules:
  - host: "*.amazonaws.com"
`)
		require.NoError(t, node.Decode(&c))
		_, err := newFromConfig(c, slog.Default(), mapBuilder(srcs), errCredBuilder)
		require.ErrorContains(t, err, "not both")
	})

	t.Run("rejects neither static nor credentials_provider", func(t *testing.T) {
		var c config
		node := yamlFromString(t, `
rules:
  - host: "*.amazonaws.com"
`)
		require.NoError(t, node.Decode(&c))
		_, err := newFromConfig(c, slog.Default(), mapBuilder(srcs), errCredBuilder)
		require.ErrorContains(t, err, "requires either")
	})

	t.Run("credentials_provider builds workload_identity path", func(t *testing.T) {
		var c config
		node := yamlFromString(t, `
credentials_provider:
  type: workload_identity
rules:
  - host: "*.amazonaws.com"
`)
		require.NoError(t, node.Decode(&c))
		stub := &stubCredsProvider{creds: aws.Credentials{AccessKeyID: "AKIA", SecretAccessKey: "shh"}}
		a, err := newFromConfig(c, slog.Default(), mapBuilder(srcs), stubCredBuilder(stub))
		require.NoError(t, err)
		require.Equal(t, "workload_identity", a.credsKind())
	})

	t.Run("allow lists compiled into sets", func(t *testing.T) {
		a := buildTransformWith(t, `
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
allowed_regions:  ["us-east-1", "eu-west-1"]
allowed_services: ["bedrock", "s3"]
rules:
  - host: "*.amazonaws.com"
`, mapBuilder(srcs))
		require.Contains(t, a.allowedRegions, "us-east-1")
		require.Contains(t, a.allowedRegions, "eu-west-1")
		require.Contains(t, a.allowedServices, "bedrock")
		require.Contains(t, a.allowedServices, "s3")
	})
}

func TestParseInboundScope(t *testing.T) {
	t.Run("extracts region and service from Authorization header", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIA.../20250102/us-east-1/bedrock/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef")

		scope, err := parseInboundScope(req)
		require.NoError(t, err)
		require.Equal(t, "us-east-1", scope.region)
		require.Equal(t, "bedrock", scope.service)
	})

	t.Run("extracts from X-Amz-Credential query param (pre-signed URL)", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://example.com/?X-Amz-Credential=AKIA...%2F20250102%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Signature=abc", nil)
		require.NoError(t, err)

		scope, err := parseInboundScope(req)
		require.NoError(t, err)
		require.Equal(t, "eu-west-1", scope.region)
		require.Equal(t, "s3", scope.service)
	})

	t.Run("rejects request with no signature", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		require.NoError(t, err)
		_, err = parseInboundScope(req)
		require.ErrorIs(t, err, errNoSigV4)
	})

	t.Run("rejects non-sigv4 Authorization header", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer abc")
		_, err = parseInboundScope(req)
		require.ErrorContains(t, err, "not a AWS4-HMAC-SHA256")
	})

	t.Run("rejects Authorization header missing Credential field", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=abc")
		_, err = parseInboundScope(req)
		require.ErrorContains(t, err, "missing Credential field in Authorization header")
	})

	t.Run("rejects malformed credential scope", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIA/foo/bar, SignedHeaders=host, Signature=abc")
		_, err = parseInboundScope(req)
		require.ErrorContains(t, err, "expected 5 path segments")
	})

	t.Run("rejects wrong terminator", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIA/20250102/us-east-1/bedrock/not_aws4, SignedHeaders=host, Signature=abc")
		_, err = parseInboundScope(req)
		require.ErrorContains(t, err, "aws4_request terminator")
	})

	t.Run("rejects empty region or service", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIA/20250102//bedrock/aws4_request, SignedHeaders=host, Signature=abc")
		_, err = parseInboundScope(req)
		require.ErrorContains(t, err, "empty region or service")
	})
}

func TestTransformRequest(t *testing.T) {
	srcs := map[string]secrets.Source{
		"AWS_ACCESS_KEY_ID":     &staticSource{name: "access", value: "AKIAEXAMPLE"},
		"AWS_SECRET_ACCESS_KEY": &staticSource{name: "secret", value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	}

	t.Run("re-signs request using scope from inbound signature", func(t *testing.T) {
		a := buildTransformWith(t, minimalYAML, mapBuilder(srcs))
		a.now = func() time.Time { return time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC) }

		req := signedRequest(t, http.MethodPost, "https://bedrock-runtime.us-east-1.amazonaws.com/model/foo/invoke", "us-east-1", "bedrock", []byte(`{"x":1}`), 1<<20)
		res, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, res.Action)

		auth := req.Header.Get("Authorization")
		require.True(t, strings.HasPrefix(auth, "AWS4-HMAC-SHA256 "), "Authorization header = %q", auth)
		require.Contains(t, auth, "Credential=AKIAEXAMPLE/20250102/us-east-1/bedrock/aws4_request")
		require.Equal(t, "20250102T030405Z", req.Header.Get("X-Amz-Date"))
		require.Empty(t, req.Header.Get("X-Amz-Security-Token"))

		// Body must remain readable downstream.
		got, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(`{"x":1}`), got)
	})

	t.Run("picks up service from any inbound signature, no per-service config", func(t *testing.T) {
		a := buildTransformWith(t, minimalYAML, mapBuilder(srcs))
		a.now = func() time.Time { return time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC) }

		// Same proxy, different service: client signed for s3 in eu-west-1.
		req := signedRequest(t, http.MethodGet, "https://bucket.s3.eu-west-1.amazonaws.com/key", "eu-west-1", "s3", nil, 1<<20)
		_, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Contains(t, req.Header.Get("Authorization"), "/eu-west-1/s3/aws4_request")
	})

	t.Run("workload_identity provider session token populates security-token header", func(t *testing.T) {
		stub := &stubCredsProvider{creds: aws.Credentials{
			AccessKeyID:     "ASIAEXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "IQoJb3JpZ2luX2VjE...",
		}}
		a := buildTransformWithBoth(t, `
credentials_provider:
  type: workload_identity
rules:
  - host: "*.amazonaws.com"
`, mapBuilder(srcs), stubCredBuilder(stub))

		req := signedRequest(t, http.MethodGet, "https://bucket.s3.us-east-1.amazonaws.com/key", "us-east-1", "s3", nil, 1<<20)
		_, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, "IQoJb3JpZ2luX2VjE...", req.Header.Get("X-Amz-Security-Token"))
		require.Contains(t, req.Header.Get("Authorization"), "ASIAEXAMPLE")
		require.Equal(t, int64(1), stub.calls.Load())
	})

	t.Run("placeholder signature is stripped before re-signing", func(t *testing.T) {
		a := buildTransformWith(t, minimalYAML, mapBuilder(srcs))
		req := signedRequest(t, http.MethodPost, "https://bedrock-runtime.us-east-1.amazonaws.com/x", "us-east-1", "bedrock", []byte("{}"), 1<<20)
		placeholderAuth := req.Header.Get("Authorization")
		require.Contains(t, placeholderAuth, "AKIAIOSFODNN7EXAMPLE", "test sanity check: inbound used placeholder creds")

		_, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)

		// The placeholder access key must not appear in the outbound signature.
		newAuth := req.Header.Get("Authorization")
		require.NotEqual(t, placeholderAuth, newAuth)
		require.NotContains(t, newAuth, "AKIAIOSFODNN7EXAMPLE")
		require.Contains(t, newAuth, "AKIAEXAMPLE")
	})

	t.Run("rejects request with no inbound signature", func(t *testing.T) {
		a := buildTransformWith(t, minimalYAML, mapBuilder(srcs))
		// No Authorization header on this request.
		req, err := http.NewRequest(http.MethodGet, "https://bedrock-runtime.us-east-1.amazonaws.com/x", nil)
		require.NoError(t, err)
		req.Body = transform.NewBufferedBody(http.NoBody, 1<<20)

		res, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionReject, res.Action)
		require.Equal(t, http.StatusBadRequest, res.Response.StatusCode)
	})

	t.Run("lets a CONNECT through even for a matched host (signs the post-MITM request)", func(t *testing.T) {
		a := buildTransformWith(t, minimalYAML, mapBuilder(srcs))
		// The proxy replays transforms against a synthetic CONNECT to make
		// tunnel-level policy decisions before MITM. A CONNECT carries no SigV4
		// signature, so aws_auth must not reject it — the signed request only
		// appears after the tunnel is established and TLS is terminated.
		req, err := http.NewRequest(http.MethodConnect, "https://bedrock-runtime.us-east-1.amazonaws.com:443", nil)
		require.NoError(t, err)

		res, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, res.Action)
		require.Empty(t, req.Header.Get("Authorization"))
	})

	t.Run("allowed_services gates which services this entry will sign for", func(t *testing.T) {
		a := buildTransformWith(t, `
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
allowed_services: ["bedrock"]
rules:
  - host: "*.amazonaws.com"
`, mapBuilder(srcs))

		// bedrock is allowed.
		req := signedRequest(t, http.MethodPost, "https://bedrock-runtime.us-east-1.amazonaws.com/x", "us-east-1", "bedrock", []byte("{}"), 1<<20)
		res, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, res.Action)

		// s3 is not.
		req2 := signedRequest(t, http.MethodGet, "https://bucket.s3.us-east-1.amazonaws.com/key", "us-east-1", "s3", nil, 1<<20)
		res, err = a.TransformRequest(context.Background(), newContext(), req2)
		require.NoError(t, err)
		require.Equal(t, transform.ActionReject, res.Action)
		require.Equal(t, http.StatusForbidden, res.Response.StatusCode)
	})

	t.Run("allowed_regions gates which regions this entry will sign for", func(t *testing.T) {
		a := buildTransformWith(t, `
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
allowed_regions: ["us-east-1"]
rules:
  - host: "*.amazonaws.com"
`, mapBuilder(srcs))

		req := signedRequest(t, http.MethodPost, "https://bedrock-runtime.eu-west-1.amazonaws.com/x", "eu-west-1", "bedrock", []byte("{}"), 1<<20)
		res, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionReject, res.Action)
		require.Equal(t, http.StatusForbidden, res.Response.StatusCode)
	})

	t.Run("rule miss leaves request untouched", func(t *testing.T) {
		a := buildTransformWith(t, minimalYAML, mapBuilder(srcs))
		req, err := http.NewRequest(http.MethodGet, "https://other.example.com/v1/foo", nil)
		require.NoError(t, err)
		req.Body = transform.NewBufferedBody(http.NoBody, 1<<20)

		res, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, res.Action)
		require.Empty(t, req.Header.Get("Authorization"))
	})

	t.Run("unsigned payload skips body buffering", func(t *testing.T) {
		var captured string
		a := buildTransformWith(t, `
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
unsigned_payload: true
rules:
  - host: "*.amazonaws.com"
`, mapBuilder(srcs))
		a.sign = func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, _ time.Time) error {
			captured = payloadHash
			req.Header.Set("Authorization", "stub")
			req.Header.Set("X-Amz-Date", "stub")
			return nil
		}

		// Chunked body with an inbound SigV4 header.
		req, err := http.NewRequest(http.MethodPut, "https://bucket.s3.us-east-1.amazonaws.com/key", strings.NewReader("streamed chunk"))
		require.NoError(t, err)
		req.ContentLength = -1
		req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader("streamed chunk")), 1<<20)
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIA/20250102/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc")

		_, err = a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, "UNSIGNED-PAYLOAD", captured)
	})

	t.Run("chunked body rejected by default", func(t *testing.T) {
		a := buildTransformWith(t, minimalYAML, mapBuilder(srcs))
		req, err := http.NewRequest(http.MethodPost, "https://bedrock-runtime.us-east-1.amazonaws.com/x", strings.NewReader("body"))
		require.NoError(t, err)
		req.ContentLength = -1
		req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader("body")), 1<<20)
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIA/20250102/us-east-1/bedrock/aws4_request, SignedHeaders=host, Signature=abc")

		res, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionReject, res.Action)
		require.Equal(t, http.StatusBadRequest, res.Response.StatusCode)
	})

	t.Run("credential failure rejects the request", func(t *testing.T) {
		srcs := map[string]secrets.Source{
			"AWS_ACCESS_KEY_ID":     &staticSource{name: "access", err: fmt.Errorf("nope")},
			"AWS_SECRET_ACCESS_KEY": &staticSource{name: "secret", value: "shh"},
		}
		a := buildTransformWith(t, minimalYAML, mapBuilder(srcs))
		req := signedRequest(t, http.MethodPost, "https://bedrock-runtime.us-east-1.amazonaws.com/x", "us-east-1", "bedrock", []byte("{}"), 1<<20)
		res, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionReject, res.Action)
		require.Equal(t, http.StatusBadGateway, res.Response.StatusCode)
	})
}

func TestTransformRequestSignsEscapedS3PathsWithoutReescaping(t *testing.T) {
	cases := []struct {
		name                   string
		url                    string
		service                string
		disableURIPathEscaping bool
	}{
		{
			name:                   "s3 plain key",
			url:                    "https://bucket.s3.us-east-1.amazonaws.com/plain.zip",
			service:                "s3",
			disableURIPathEscaping: true,
		},
		{
			name:                   "s3 key with spaces",
			url:                    "https://bucket.s3.us-east-1.amazonaws.com/JULY%2027.zip",
			service:                "s3",
			disableURIPathEscaping: true,
		},
		{
			name:                   "s3 key with escaped slash",
			url:                    "https://bucket.s3.us-east-1.amazonaws.com/folder%2Ffile.zip",
			service:                "s3",
			disableURIPathEscaping: true,
		},
		{
			name:    "other AWS services retain default escaping",
			url:     "https://bedrock-runtime.us-east-1.amazonaws.com/model/a%20b/invoke",
			service: "bedrock",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srcs := map[string]secrets.Source{
				"AWS_ACCESS_KEY_ID":     &staticSource{name: "access", value: "AKIAEXAMPLE"},
				"AWS_SECRET_ACCESS_KEY": &staticSource{name: "secret", value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
			}
			a := buildTransformWith(t, minimalYAML, mapBuilder(srcs))
			signingTime := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
			a.now = func() time.Time { return signingTime }

			req := signedRequest(t, http.MethodGet, tc.url, "us-east-1", tc.service, nil, 1<<20)
			escapedPath := req.URL.EscapedPath()
			expected := req.Clone(context.Background())
			stripInboundSignatureHeaders(expected)
			expected.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
			signer := v4.NewSigner(func(o *v4.SignerOptions) {
				o.DisableURIPathEscaping = tc.disableURIPathEscaping
			})
			creds := aws.Credentials{
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			}
			require.NoError(t, signer.SignHTTP(context.Background(), creds, expected, emptyPayloadSHA256, tc.service, "us-east-1", signingTime))

			res, err := a.TransformRequest(context.Background(), newContext(), req)
			require.NoError(t, err)
			require.Equal(t, transform.ActionContinue, res.Action)
			require.Equal(t, escapedPath, req.URL.EscapedPath())
			require.Equal(t, expected.Header.Get("Authorization"), req.Header.Get("Authorization"))
		})
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
