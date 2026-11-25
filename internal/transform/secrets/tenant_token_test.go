package secrets

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/tenant"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func TestTenantTokenSource(t *testing.T) {
	src, err := newTenantTokenBuilder(slog.Default()).Build(yamlNode(t, map[string]string{"type": "tenant_token"}))
	require.NoError(t, err)
	require.Equal(t, "tenant_token", src.Name())

	ctx1 := tenant.WithToken(context.Background(), &tenant.Token{Raw: "first-token"})
	got, err := src.Get(ctx1)
	require.NoError(t, err)
	require.Equal(t, "first-token", got)

	// The same source must return the next request's token, not a cached one.
	ctx2 := tenant.WithToken(context.Background(), &tenant.Token{Raw: "second-token"})
	got, err = src.Get(ctx2)
	require.NoError(t, err)
	require.Equal(t, "second-token", got)

	_, err = src.Get(context.Background())
	require.ErrorContains(t, err, "tenant token")
}

func TestTenantTokenSourceRejectsJSONKey(t *testing.T) {
	_, err := BuildSource(yamlNode(t, map[string]string{"type": "tenant_token", "json_key": "token"}), slog.Default())
	require.ErrorContains(t, err, "json_key")
}

func tenantTokenSecrets(t *testing.T, requireSecret bool, inject bool) *Secrets {
	t.Helper()
	entry := secretEntry{
		Source: yamlNode(t, map[string]string{"type": "tenant_token"}),
		Rules:  []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}
	if inject {
		entry.Inject = &injectConfig{
			Header:    "X-Tenant-Token",
			Formatter: "Bearer {{ .Value }}",
			Require:   requireSecret,
		}
	} else {
		entry.Replace = &replaceConfig{
			ProxyValue:   "proxy-tenant-token",
			MatchHeaders: []string{"Authorization"},
			Require:      requireSecret,
		}
	}
	s, err := newFromConfig(secretsConfig{Secrets: []secretEntry{entry}}, defaultRegistry(slog.Default()))
	require.NoError(t, err)
	return s
}

func encodedAnnotations(t *testing.T, tctx *transform.TransformContext) string {
	t.Helper()
	b, err := json.Marshal(tctx.DrainAnnotations())
	require.NoError(t, err)
	return string(b)
}

func TestSecrets_TenantTokenInject(t *testing.T) {
	const raw = "raw-tenant-token"
	s := tenantTokenSecrets(t, true, true)
	req := openaiReq("GET", "/v1/chat")
	tctx := &transform.TransformContext{}
	ctx := tenant.WithToken(context.Background(), &tenant.Token{Raw: raw})

	res, err := s.TransformRequest(ctx, tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer "+raw, req.Header.Get("X-Tenant-Token"))

	annotations := encodedAnnotations(t, tctx)
	require.Contains(t, annotations, "tenant_token")
	require.NotContains(t, annotations, raw)
}

func TestSecrets_TenantTokenReplace(t *testing.T) {
	const raw = "raw-tenant-token"
	s := tenantTokenSecrets(t, true, false)
	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-tenant-token")
	tctx := &transform.TransformContext{}
	ctx := tenant.WithToken(context.Background(), &tenant.Token{Raw: raw})

	res, err := s.TransformRequest(ctx, tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer "+raw, req.Header.Get("Authorization"))

	annotations := encodedAnnotations(t, tctx)
	require.Contains(t, annotations, "tenant_token")
	require.NotContains(t, annotations, raw)
}

func TestSecrets_TenantTokenRequireRejectsWithoutContext(t *testing.T) {
	s := tenantTokenSecrets(t, true, false)
	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-tenant-token")
	tctx := &transform.TransformContext{}

	res, err := s.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)

	annotations := encodedAnnotations(t, tctx)
	require.Contains(t, annotations, `"rejected":"tenant_token"`)
	require.Contains(t, annotations, `"reject_reason":"secret_unavailable"`)
}

func TestSecrets_TenantTokenSkippedWithoutContext(t *testing.T) {
	s := tenantTokenSecrets(t, false, false)
	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-tenant-token")
	tctx := &transform.TransformContext{}

	res, err := s.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer proxy-tenant-token", req.Header.Get("Authorization"))

	annotations := encodedAnnotations(t, tctx)
	require.Contains(t, annotations, `"secret_unavailable":["tenant_token"]`)
}

func TestSecrets_TenantTokenValueNeverAnnotated(t *testing.T) {
	const raw = "super-secret-tenant-token"
	s := tenantTokenSecrets(t, true, false)
	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer some-other-token")
	tctx := &transform.TransformContext{}
	ctx := tenant.WithToken(context.Background(), &tenant.Token{Raw: raw})

	res, err := s.TransformRequest(ctx, tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)

	annotations := encodedAnnotations(t, tctx)
	require.Contains(t, annotations, "tenant_token")
	require.NotContains(t, annotations, raw)
}
