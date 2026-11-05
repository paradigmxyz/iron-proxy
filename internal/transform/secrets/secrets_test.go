package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/headers"
	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// fakeBuilder is a test secretSourceBuilder. Build only validates that the
// source has a recognizable name field; the lookup against secrets (and any
// failure) is deferred to Get.
type fakeBuilder struct {
	mu         sync.Mutex
	secrets    map[string]string
	fetchCalls map[string]int
}

func (f *fakeBuilder) extractName(raw yaml.Node) (string, error) {
	var env envConfig
	if err := raw.Decode(&env); err == nil && env.Var != "" {
		return env.Var, nil
	}
	var sm awsSMConfig
	if err := raw.Decode(&sm); err == nil && sm.SecretID != "" {
		return sm.SecretID, nil
	}
	var ssm awsSSMConfig
	if err := raw.Decode(&ssm); err == nil && ssm.Name != "" {
		return ssm.Name, nil
	}
	return "", &resolveError{"unknown"}
}

func (f *fakeBuilder) Build(raw yaml.Node) (secretSource, error) {
	name, err := f.extractName(raw)
	if err != nil {
		return nil, err
	}
	return newLazyValue(name, 0, defaultFailureTTL, slog.Default(), func(context.Context) (string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.fetchCalls == nil {
			f.fetchCalls = make(map[string]int)
		}
		f.fetchCalls[name]++
		val, ok := f.secrets[name]
		if !ok || val == "" {
			return "", &resolveError{name}
		}
		return val, nil
	}), nil
}

type resolveError struct{ name string }

func (e *resolveError) Error() string { return e.name + " not found" }

func testRegistry() sourceBuilderRegistry {
	return sourceBuilderRegistry{
		"env": &fakeBuilder{secrets: map[string]string{
			"OPENAI_API_KEY":    "sk-real-openai-key",
			"ANTHROPIC_API_KEY": "sk-real-anthropic-key",
			"INTERNAL_TOKEN":    "real-internal-token",
		}},
		"aws_sm": &fakeBuilder{secrets: map[string]string{
			"arn:aws:sm:test": "aws-secret-value",
		}},
		"aws_ssm": &fakeBuilder{secrets: map[string]string{
			"/myapp/api-key": "ssm-secret-value",
		}},
	}
}

func envSource(varName string) yaml.Node {
	return yamlNode(&testing.T{}, map[string]string{"type": "env", "var": varName})
}

func awsSMSource(secretID string) yaml.Node {
	return yamlNode(&testing.T{}, map[string]string{"type": "aws_sm", "secret_id": secretID})
}

func awsSSMSource(name string) yaml.Node {
	return yamlNode(&testing.T{}, map[string]string{"type": "aws_ssm", "name": name})
}

// defaultEntry returns the most common secretEntry used across tests.
// Use the opts functions to override specific fields.
func defaultEntry(opts ...func(*secretEntry)) secretEntry {
	e := secretEntry{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}
	for _, opt := range opts {
		opt(&e)
	}
	return e
}

func makeSecrets(t *testing.T, entries []secretEntry) *Secrets {
	t.Helper()
	cfg := secretsConfig{Secrets: entries}
	s, err := newFromConfig(cfg, testRegistry())
	require.NoError(t, err)
	return s
}

func doTransform(t *testing.T, s *Secrets, req *http.Request) {
	t.Helper()
	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func openaiReq(method, path string) *http.Request {
	req := httptest.NewRequest(method, "http://api.openai.com"+path, nil)
	req.Host = "api.openai.com"
	return req
}

func TestSecrets_HeaderSwap(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry()})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_QueryParamSwap(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source: envSource("OPENAI_API_KEY"),
		Rules:  []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		Replace: &replaceConfig{
			ProxyValue: "proxy-openai-abc123",
			MatchQuery: true,
		},
	}})

	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat?token=proxy-openai-abc123&other=value", nil)
	req.Host = "api.openai.com"

	doTransform(t, s, req)

	require.Contains(t, req.URL.RawQuery, "sk-real-openai-key")
	require.NotContains(t, req.URL.RawQuery, "proxy-openai-abc123")
	require.Contains(t, req.URL.RawQuery, "other=value")
}

func TestSecrets_QueryParamNotSwappedByDefault(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = nil
	})})

	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat?token=proxy-openai-abc123&other=value", nil)
	req.Host = "api.openai.com"

	doTransform(t, s, req)

	require.Contains(t, req.URL.RawQuery, "proxy-openai-abc123")
	require.NotContains(t, req.URL.RawQuery, "sk-real-openai-key")
}

func TestSecrets_BodySwap(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = nil
		e.MatchBody = true
	})})

	body := `{"api_key": "proxy-openai-abc123", "model": "gpt-4"}`
	rb := transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), 1<<20)

	req := openaiReq("POST", "/v1/chat")
	req.Body = rb
	req.ContentLength = int64(len(body))

	doTransform(t, s, req)

	result, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Contains(t, string(result), "sk-real-openai-key")
	require.NotContains(t, string(result), "proxy-openai-abc123")
	require.Contains(t, string(result), `"model": "gpt-4"`)
}

func TestSecrets_HostMatch(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry()})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_HostNoMatch(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry()})

	req := httptest.NewRequest("GET", "http://evil.com/steal", nil)
	req.Host = "evil.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)

	// Token should NOT be replaced — host doesn't match
	require.Equal(t, "Bearer proxy-openai-abc123", req.Header.Get("Authorization"))
}

func TestSecrets_WildcardHost(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.Source = envSource("ANTHROPIC_API_KEY")
		e.ProxyValue = "proxy-anthropic-xyz789"
		e.MatchHeaders = []string{"X-Api-Key"}
		e.Rules = []hostmatch.RuleConfig{{Host: "*.anthropic.com"}}
	})})

	req := httptest.NewRequest("GET", "http://api.anthropic.com/v1/messages", nil)
	req.Host = "api.anthropic.com"
	req.Header.Set("X-Api-Key", "proxy-anthropic-xyz789")

	doTransform(t, s, req)
	require.Equal(t, "sk-real-anthropic-key", req.Header.Get("X-Api-Key"))
}

func TestSecrets_MultipleSecrets(t *testing.T) {
	s := makeSecrets(t, []secretEntry{
		defaultEntry(),
		defaultEntry(func(e *secretEntry) {
			e.Source = envSource("INTERNAL_TOKEN")
			e.ProxyValue = "proxy-internal-tok"
			e.MatchHeaders = []string{"X-Internal"}
		}),
	})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")
	req.Header.Set("X-Internal", "proxy-internal-tok")

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	require.Equal(t, "real-internal-token", req.Header.Get("X-Internal"))
}

func TestSecrets_MatchHeadersFiltering(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry()})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")
	req.Header.Set("X-Custom", "proxy-openai-abc123") // not in match_headers

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	// X-Custom should NOT be touched
	require.Equal(t, "proxy-openai-abc123", req.Header.Get("X-Custom"))
}

func TestSecrets_EmptyMatchHeadersSearchesAll(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = []string{} // empty = all headers
	})})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")
	req.Header.Set("X-Custom", "proxy-openai-abc123")

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	require.Equal(t, "sk-real-openai-key", req.Header.Get("X-Custom"))
}

func TestSecrets_RegexMatchHeaders(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = []string{`/^X-.*-Key$/`}
	})})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("X-Api-Key", "proxy-openai-abc123")
	req.Header.Set("X-Other-Key", "proxy-openai-abc123")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123") // not matched
	req.Header.Set("X-Trace", "proxy-openai-abc123")              // not matched

	doTransform(t, s, req)

	require.Equal(t, "sk-real-openai-key", req.Header.Get("X-Api-Key"))
	require.Equal(t, "sk-real-openai-key", req.Header.Get("X-Other-Key"))
	require.Equal(t, "Bearer proxy-openai-abc123", req.Header.Get("Authorization"))
	require.Equal(t, "proxy-openai-abc123", req.Header.Get("X-Trace"))
}

func TestSecrets_RegexMatchHeaders_CaseInsensitiveByDefault(t *testing.T) {
	// Lowercase pattern matches the canonical "Authorization" header.
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = []string{`/^authorization$/`}
	})})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_RegexMatchHeaders_MixedWithLiteral(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = []string{"Authorization", `/^X-Api-.*$/`}
	})})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")
	req.Header.Set("X-Api-Key", "proxy-openai-abc123")
	req.Header.Set("X-Custom", "proxy-openai-abc123") // not matched

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	require.Equal(t, "sk-real-openai-key", req.Header.Get("X-Api-Key"))
	require.Equal(t, "proxy-openai-abc123", req.Header.Get("X-Custom"))
}

func TestSecrets_RegexMatchHeaders_OverlappingPatternsDontDoubleSwap(t *testing.T) {
	// Two patterns that both match "X-Api-Key": ensure the swap runs once and
	// doesn't replace twice (which would be idempotent for non-Basic, but the
	// location annotation would duplicate).
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = []string{"X-Api-Key", `/^X-.*$/`}
	})})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("X-Api-Key", "proxy-openai-abc123")

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "sk-real-openai-key", req.Header.Get("X-Api-Key"))
}

func TestSecrets_RegexMatchHeaders_RequireRejectsWhenNoMatch(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = []string{`/^X-.*-Key$/`}
		e.Require = true
	})})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("X-Api-Key", "no-token-here")

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
}

func TestSecrets_RegexMatchHeaders_InvalidRegex(t *testing.T) {
	cfg := secretsConfig{Secrets: []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-tok",
		MatchHeaders: []string{`/[invalid/`},
		Rules:        []hostmatch.RuleConfig{{Host: "example.com"}},
	}}}
	_, err := newFromConfig(cfg, testRegistry())
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid match_headers regex")
}

func TestSecrets_MatchHeaders_PreservesUserCasing(t *testing.T) {
	// A match_headers entry with non-canonical casing matches the header
	// case-insensitively but is written back with the user's casing.
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = []string{"x-api-KEY"}
	})})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("X-Api-Key", "proxy-openai-abc123") // canonical casing inbound

	doTransform(t, s, req)

	// Value swapped, and stored under the user-specified casing only.
	// req.Header.Get canonicalizes its lookup, so it no longer finds it.
	_, canonicalExists := req.Header["X-Api-Key"]
	require.False(t, canonicalExists, "canonical key should be removed")
	require.Equal(t, []string{"sk-real-openai-key"}, headers.Values(req.Header, "x-api-KEY"))
}

func TestSecrets_MatchHeaders_UserCasingInLocations(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = []string{"x-api-key"}
	})})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("X-Api-Key", "proxy-openai-abc123")

	tctx := &transform.TransformContext{}
	res, err := s.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	// The swapped location annotation reports the user's header casing.
	encoded, err := json.Marshal(tctx.DrainAnnotations()["swapped"])
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"header:x-api-key"`)
}

func TestSecrets_RegexMatchHeaders_KeepsExistingCasing(t *testing.T) {
	// Regex matches carry no user-specified casing, so the header's
	// existing casing on the request is preserved.
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = []string{`/^x-api-key$/`}
	})})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("X-Api-Key", "proxy-openai-abc123")

	doTransform(t, s, req)

	require.Equal(t, []string{"sk-real-openai-key"}, req.Header["X-Api-Key"])
}

func TestSecrets_ConfigErrors(t *testing.T) {
	tests := []struct {
		name   string
		cfg    secretsConfig
		errMsg string
	}{
		{
			name: "no mode specified",
			cfg: secretsConfig{Secrets: []secretEntry{{
				Source: envSource("OPENAI_API_KEY"),
				Rules:  []hostmatch.RuleConfig{{Host: "example.com"}},
			}}},
			errMsg: "must specify either inject or replace",
		},
		{
			name: "unsupported source type",
			cfg: secretsConfig{Secrets: []secretEntry{{
				Source:     yamlNode(&testing.T{}, map[string]string{"type": "vault"}),
				ProxyValue: "proxy-value",
				Rules:      []hostmatch.RuleConfig{{Host: "example.com"}},
			}}},
			errMsg: "unsupported source type",
		},
		{
			name: "missing source type",
			cfg: secretsConfig{Secrets: []secretEntry{{
				Source:     yamlNode(&testing.T{}, map[string]string{"var": "FOO"}),
				ProxyValue: "proxy-value",
				Rules:      []hostmatch.RuleConfig{{Host: "example.com"}},
			}}},
			errMsg: "source.type is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newFromConfig(tt.cfg, testRegistry())
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestSecrets_BodyTooLarge(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = nil
		e.MatchBody = true
	})})

	// Create a body larger than the max (1 MiB)
	bigBody := strings.Repeat("x", (1<<20)+100)
	rb := transform.NewBufferedBody(io.NopCloser(strings.NewReader(bigBody)), 1<<20)

	req := openaiReq("POST", "/v1/chat")
	req.Body = rb

	// Should not error — just skip body substitution
	doTransform(t, s, req)
}

func TestSecrets_HostWithPort(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry()})

	req := httptest.NewRequest("GET", "http://api.openai.com:443/v1/chat", nil)
	req.Host = "api.openai.com:443"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_ResponseIsNoop(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = nil
	})})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{StatusCode: http.StatusOK}
	res, err := s.TransformResponse(context.Background(), &transform.TransformContext{}, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestSecrets_ConcurrentSafety(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry()})

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := openaiReq("GET", "/v1/chat")
			req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

			doTransform(t, s, req)

			require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
		}()
	}
	wg.Wait()
}

func TestSecrets_BasicAuthSwap(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry()})

	// Basic auth: "user:proxy-openai-abc123" base64-encoded
	creds := base64.StdEncoding.EncodeToString([]byte("user:proxy-openai-abc123"))
	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Basic "+creds)

	doTransform(t, s, req)

	got := req.Header.Get("Authorization")
	require.True(t, strings.HasPrefix(got, "Basic "))
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "Basic "))
	require.NoError(t, err)
	require.Equal(t, "user:sk-real-openai-key", string(decoded))
}

func TestSecrets_BasicAuthNoMatch(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry()})

	// Basic auth with no proxy token inside
	creds := base64.StdEncoding.EncodeToString([]byte("user:some-other-password"))
	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Basic "+creds)

	doTransform(t, s, req)

	// Should be unchanged
	require.Equal(t, "Basic "+creds, req.Header.Get("Authorization"))
}

func TestSecrets_BasicAuthAllHeaders(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = []string{} // all headers
	})})

	creds := base64.StdEncoding.EncodeToString([]byte("proxy-openai-abc123:secret"))
	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Basic "+creds)

	doTransform(t, s, req)

	got := req.Header.Get("Authorization")
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "Basic "))
	require.NoError(t, err)
	require.Equal(t, "sk-real-openai-key:secret", string(decoded))
}

func TestSecrets_BasicAuthIgnoredOnNonAuthHeader(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = []string{} // all headers
	})})

	// "Basic <base64>" on a non-Authorization header should not be decoded
	creds := base64.StdEncoding.EncodeToString([]byte("proxy-openai-abc123:secret"))
	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("X-Custom", "Basic "+creds)

	doTransform(t, s, req)

	// The base64 payload doesn't contain the literal proxy token, so no swap
	require.Equal(t, "Basic "+creds, req.Header.Get("X-Custom"))
}

func TestSecrets_RequireRejectsWithoutProxyToken(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.Require = true
	})})

	// Request to matching host but with a different credential — should be rejected.
	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer sk-some-other-key")

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
}

func TestSecrets_RequireContinuesWithProxyToken(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.Require = true
	})})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_RequireDefaultFalseAllowsThrough(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry()})

	// Request without proxy token — should still pass (require is false).
	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer sk-some-other-key")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-some-other-key", req.Header.Get("Authorization"))
}

func TestSecrets_RequireNonMatchingHostAllowsThrough(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.Require = true
	})})

	// Request to a different host — host doesn't match, so require doesn't apply.
	req := httptest.NewRequest("GET", "http://other.com/v1/chat", nil)
	req.Host = "other.com"
	req.Header.Set("Authorization", "Bearer sk-some-other-key")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-some-other-key", req.Header.Get("Authorization"))
}

func TestSecrets_RequireRejectsNoHeaders(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.Require = true
	})})

	// Request to matching host with no Authorization header at all.
	req := openaiReq("GET", "/v1/chat")

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
}

func TestSecrets_RequireAllowsConnectWithoutHeaderWhenConfigured(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.Require = true
		e.AllowConnectWithoutHeader = true
	})})

	req := httptest.NewRequest(http.MethodConnect, "http://api.openai.com:443", nil)
	req.Host = "api.openai.com:443"

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestSecrets_RequireRejectsConnectWithoutHeaderByDefault(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.Require = true
	})})

	req := httptest.NewRequest(http.MethodConnect, "http://api.openai.com:443", nil)
	req.Host = "api.openai.com:443"

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
}

func TestSecrets_RequireWithBodySwap(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.MatchHeaders = nil
		e.MatchBody = true
		e.Require = true
	})})

	body := `{"api_key": "proxy-openai-abc123"}`
	rb := transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), 1<<20)

	req := openaiReq("POST", "/v1/chat")
	req.Body = rb

	doTransform(t, s, req)

	result, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Contains(t, string(result), "sk-real-openai-key")
}

func TestSecrets_Name(t *testing.T) {
	s := makeSecrets(t, nil)
	require.Equal(t, "secrets", s.Name())
}

// --- Rules matching tests ---

func TestSecrets_MethodFiltering(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.Rules = []hostmatch.RuleConfig{{Host: "api.openai.com", Methods: []string{"POST"}}}
	})})

	// GET request should NOT match the rule
	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer proxy-openai-abc123", req.Header.Get("Authorization"))

	// POST request should match
	req = openaiReq("POST", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_PathFiltering(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry(func(e *secretEntry) {
		e.Rules = []hostmatch.RuleConfig{{Host: "api.openai.com", Paths: []string{"/v1/*"}}}
	})})

	// Path outside /v1/* should NOT match
	req := openaiReq("GET", "/v2/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer proxy-openai-abc123", req.Header.Get("Authorization"))

	// Path inside /v1/* should match
	req = openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_MixedSourceTypes(t *testing.T) {
	s := makeSecrets(t, []secretEntry{
		defaultEntry(),
		defaultEntry(func(e *secretEntry) {
			e.Source = awsSMSource("arn:aws:sm:test")
			e.ProxyValue = "proxy-aws-tok"
			e.MatchHeaders = []string{"X-Api-Key"}
		}),
		defaultEntry(func(e *secretEntry) {
			e.Source = awsSSMSource("/myapp/api-key")
			e.ProxyValue = "proxy-ssm-tok"
			e.MatchHeaders = []string{"X-SSM-Key"}
		}),
	})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")
	req.Header.Set("X-Api-Key", "proxy-aws-tok")
	req.Header.Set("X-SSM-Key", "proxy-ssm-tok")

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	require.Equal(t, "aws-secret-value", req.Header.Get("X-Api-Key"))
	// match_headers preserves the user's casing, so "X-SSM-Key" is written
	// back verbatim rather than canonicalized to "X-Ssm-Key".
	require.Equal(t, []string{"ssm-secret-value"}, headers.Values(req.Header, "X-SSM-Key"))
}

// --- End-to-end tests with real awsSMBuilder and mock AWS client ---

func awsSMRegistry(client smClient) sourceBuilderRegistry {
	return sourceBuilderRegistry{"aws_sm": &awsSMBuilder{
		clientFor: func(_ context.Context, _ string) (smClient, error) {
			return client, nil
		},
		logger: slog.Default(),
	}}
}

func makeAWSSMSecrets(t *testing.T, client smClient, entries []secretEntry) *Secrets {
	t.Helper()
	cfg := secretsConfig{Secrets: entries}
	s, err := newFromConfig(cfg, awsSMRegistry(client))
	require.NoError(t, err)
	return s
}

func TestAWSSM_EndToEnd_HeaderSwap(t *testing.T) {
	client := &mockSMClient{fn: func(_ context.Context, input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
		require.Equal(t, "arn:aws:sm:us-east-1:123:secret:openai", aws.ToString(input.SecretId))
		return &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String("sk-real-openai-key"),
		}, nil
	}}

	s := makeAWSSMSecrets(t, client, []secretEntry{{
		Source:       yamlNode(t, map[string]string{"type": "aws_sm", "secret_id": "arn:aws:sm:us-east-1:123:secret:openai"}),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	req := openaiReq("POST", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestAWSSM_EndToEnd_JSONKey(t *testing.T) {
	client := staticSMClient(&secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(`{"api_key": "sk-from-json", "other": "ignored"}`),
	}, nil)

	s := makeAWSSMSecrets(t, client, []secretEntry{{
		Source: yamlNode(t, map[string]string{
			"type":      "aws_sm",
			"secret_id": "arn:aws:sm:us-east-1:123:secret:multi",
			"json_key":  "api_key",
		}),
		ProxyValue:   "proxy-tok",
		MatchHeaders: []string{"X-Api-Key"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.example.com/v1/data", nil)
	req.Host = "api.example.com"
	req.Header.Set("X-Api-Key", "proxy-tok")

	doTransform(t, s, req)
	require.Equal(t, "sk-from-json", req.Header.Get("X-Api-Key"))
}

func TestAWSSM_EndToEnd_BodySwap(t *testing.T) {
	client := staticSMClient(&secretsmanager.GetSecretValueOutput{
		SecretString: aws.String("real-secret"),
	}, nil)

	s := makeAWSSMSecrets(t, client, []secretEntry{{
		Source:     yamlNode(t, map[string]string{"type": "aws_sm", "secret_id": "arn:test"}),
		ProxyValue: "proxy-tok",
		MatchBody:  true,
		Rules:      []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}})

	body := `{"key": "proxy-tok"}`
	rb := transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), 1<<20)
	req := httptest.NewRequest("POST", "http://api.example.com/v1/data", nil)
	req.Host = "api.example.com"
	req.Body = rb

	doTransform(t, s, req)

	result, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Contains(t, string(result), "real-secret")
	require.NotContains(t, string(result), "proxy-tok")
}

func TestAWSSM_EndToEnd_TTLRefresh(t *testing.T) {
	var callCount atomic.Int32
	client := &mockSMClient{fn: func(_ context.Context, _ *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
		n := callCount.Add(1)
		// Return a different value each call so we can observe the refresh.
		return &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String(fmt.Sprintf("value-%d", n)),
		}, nil
	}}

	s := makeAWSSMSecrets(t, client, []secretEntry{{
		Source: yamlNode(t, map[string]string{
			"type":      "aws_sm",
			"secret_id": "arn:test",
			"ttl":       "1ns", // expires immediately so each request triggers refresh
		}),
		ProxyValue:   "proxy-tok",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}})
	require.Equal(t, int32(0), callCount.Load(), "lazy: no fetch before first request")

	// First request: triggers initial fetch (call 1, value-1).
	req := httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-tok")
	doTransform(t, s, req)
	require.Equal(t, "Bearer value-1", req.Header.Get("Authorization"))

	// Second request: TTL already expired, triggers refresh (call 2, value-2).
	req = httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-tok")
	doTransform(t, s, req)
	require.Equal(t, "Bearer value-2", req.Header.Get("Authorization"))

	require.GreaterOrEqual(t, callCount.Load(), int32(2))
}

func TestAWSSM_EndToEnd_TTLServesStaleOnError(t *testing.T) {
	var callCount atomic.Int32
	client := &mockSMClient{fn: func(_ context.Context, _ *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
		n := callCount.Add(1)
		// First fetch (lazy, on first request) succeeds.
		if n == 1 {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("good-value"),
			}, nil
		}
		// All subsequent refresh attempts fail.
		return nil, fmt.Errorf("aws transient error")
	}}

	s := makeAWSSMSecrets(t, client, []secretEntry{{
		Source: yamlNode(t, map[string]string{
			"type":      "aws_sm",
			"secret_id": "arn:test",
			"ttl":       "1ns",
		}),
		ProxyValue:   "proxy-tok",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}})
	require.Equal(t, int32(0), callCount.Load(), "lazy: no fetch before first request")

	// First request: lazy fetch succeeds and caches "good-value".
	req := httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-tok")
	doTransform(t, s, req)
	require.Equal(t, "Bearer good-value", req.Header.Get("Authorization"))

	// Second request: TTL expired, refresh fails, stale "good-value" served.
	req = httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-tok")
	doTransform(t, s, req)
	require.Equal(t, "Bearer good-value", req.Header.Get("Authorization"))

	// Third request: same — refresh fails again, stale value still served.
	req = httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-tok")
	doTransform(t, s, req)
	require.Equal(t, "Bearer good-value", req.Header.Get("Authorization"))

	// At least 2 refresh attempts beyond the initial successful fetch.
	require.GreaterOrEqual(t, callCount.Load(), int32(3))
}

func TestAWSSM_EndToEnd_RequireRejectsWithoutToken(t *testing.T) {
	client := staticSMClient(&secretsmanager.GetSecretValueOutput{
		SecretString: aws.String("real-secret"),
	}, nil)

	s := makeAWSSMSecrets(t, client, []secretEntry{{
		Source:       yamlNode(t, map[string]string{"type": "aws_sm", "secret_id": "arn:test"}),
		ProxyValue:   "proxy-tok",
		MatchHeaders: []string{"Authorization"},
		Require:      true,
		Rules:        []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer wrong-token")

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
}

// --- End-to-end tests with real awsSSMBuilder and mock AWS client ---

func awsSSMRegistry(client ssmClient) sourceBuilderRegistry {
	return sourceBuilderRegistry{"aws_ssm": &awsSSMBuilder{
		clientFor: func(_ context.Context, _ string) (ssmClient, error) {
			return client, nil
		},
		logger: slog.Default(),
	}}
}

func makeAWSSSMSecrets(t *testing.T, client ssmClient, entries []secretEntry) *Secrets {
	t.Helper()
	cfg := secretsConfig{Secrets: entries}
	s, err := newFromConfig(cfg, awsSSMRegistry(client))
	require.NoError(t, err)
	return s
}

func TestAWSSSM_EndToEnd_JSONKeyHeaderSwap(t *testing.T) {
	client := &mockSSMClient{fn: func(_ context.Context, input *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
		require.Equal(t, "/myapp/api-key", aws.ToString(input.Name))
		require.True(t, aws.ToBool(input.WithDecryption))
		return &ssm.GetParameterOutput{
			Parameter: &ssmtypes.Parameter{Value: aws.String(`{"api_key":"sk-from-ssm"}`)},
		}, nil
	}}

	s := makeAWSSSMSecrets(t, client, []secretEntry{{
		Source: yamlNode(t, map[string]string{
			"type":     "aws_ssm",
			"name":     "/myapp/api-key",
			"region":   "us-east-1",
			"json_key": "api_key",
			"ttl":      "15m",
		}),
		Replace: &replaceConfig{
			ProxyValue:   "proxy-token-789",
			MatchHeaders: []string{"Authorization"},
		},
		Rules: []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.example.com/v1/data", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-token-789")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-from-ssm", req.Header.Get("Authorization"))
}

// --- Inject mode tests ---

func injectEntry(opts ...func(*secretEntry)) secretEntry {
	e := secretEntry{
		Source: envSource("OPENAI_API_KEY"),
		Inject: &injectConfig{
			Header:    "Authorization",
			Formatter: "Bearer {{ .Value }}",
		},
		Rules: []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}
	for _, opt := range opts {
		opt(&e)
	}
	return e
}

func TestInject_HeaderWithFormatter(t *testing.T) {
	s := makeSecrets(t, []secretEntry{injectEntry()})

	req := openaiReq("GET", "/v1/chat")
	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestInject_HeaderNoFormatter(t *testing.T) {
	s := makeSecrets(t, []secretEntry{injectEntry(func(e *secretEntry) {
		e.Inject.Formatter = ""
		e.Inject.Header = "X-Api-Key"
	})})

	req := openaiReq("GET", "/v1/chat")
	doTransform(t, s, req)

	require.Equal(t, "sk-real-openai-key", req.Header.Get("X-Api-Key"))
}

func TestInject_HeaderPreservesUserCasing(t *testing.T) {
	// The configured header casing is sent over the wire verbatim rather
	// than being canonicalized.
	s := makeSecrets(t, []secretEntry{injectEntry(func(e *secretEntry) {
		e.Inject.Formatter = ""
		e.Inject.Header = "X-API-KEY"
	})})

	req := openaiReq("GET", "/v1/chat")
	doTransform(t, s, req)

	// Stored under the user's casing; canonical lookup no longer finds it.
	require.Equal(t, []string{"sk-real-openai-key"}, headers.Values(req.Header, "X-API-KEY"))
	_, canonicalExists := req.Header["X-Api-Key"]
	require.False(t, canonicalExists, "canonical key should not be present")
}

func TestInject_HeaderReplacesExistingCanonicalValue(t *testing.T) {
	// An inbound header under the canonical name is replaced, not duplicated,
	// when the configured casing differs.
	s := makeSecrets(t, []secretEntry{injectEntry(func(e *secretEntry) {
		e.Inject.Formatter = ""
		e.Inject.Header = "X-API-KEY"
	})})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("X-Api-Key", "stale-value")
	doTransform(t, s, req)

	require.Equal(t, []string{"sk-real-openai-key"}, headers.Values(req.Header, "X-API-KEY"))
	_, canonicalExists := req.Header["X-Api-Key"]
	require.False(t, canonicalExists, "stale canonical header should be removed")
}

func TestInject_Base64Formatter(t *testing.T) {
	s := makeSecrets(t, []secretEntry{injectEntry(func(e *secretEntry) {
		e.Inject.Formatter = `Basic {{ base64 "x-credential:" .Value }}`
	})})

	req := openaiReq("GET", "/v1/chat")
	doTransform(t, s, req)

	got := req.Header.Get("Authorization")
	require.True(t, strings.HasPrefix(got, "Basic "))
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "Basic "))
	require.NoError(t, err)
	require.Equal(t, "x-credential:sk-real-openai-key", string(decoded))
}

func TestInject_QueryParam(t *testing.T) {
	s := makeSecrets(t, []secretEntry{injectEntry(func(e *secretEntry) {
		e.Inject = &injectConfig{QueryParam: "key"}
	})})

	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat?existing=value", nil)
	req.Host = "api.openai.com"
	doTransform(t, s, req)

	require.Equal(t, "sk-real-openai-key", req.URL.Query().Get("key"))
	require.Equal(t, "value", req.URL.Query().Get("existing"))
}

func TestInject_OverwritesExistingHeader(t *testing.T) {
	s := makeSecrets(t, []secretEntry{injectEntry()})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer client-sent-token")
	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestInject_NoMatchingHost(t *testing.T) {
	s := makeSecrets(t, []secretEntry{injectEntry()})

	req := httptest.NewRequest("GET", "http://evil.com/steal", nil)
	req.Host = "evil.com"
	doTransform(t, s, req)

	require.Empty(t, req.Header.Get("Authorization"))
}

func TestInject_MixedWithReplace(t *testing.T) {
	s := makeSecrets(t, []secretEntry{
		// Inject mode for OpenAI
		injectEntry(),
		// Replace mode for internal service
		defaultEntry(func(e *secretEntry) {
			e.Source = envSource("INTERNAL_TOKEN")
			e.ProxyValue = "proxy-internal-tok"
			e.MatchHeaders = []string{"X-Internal"}
		}),
	})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("X-Internal", "proxy-internal-tok")
	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	require.Equal(t, "real-internal-token", req.Header.Get("X-Internal"))
}

func TestInject_ReplaceBlock(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source: envSource("OPENAI_API_KEY"),
		Replace: &replaceConfig{
			ProxyValue:   "proxy-openai-abc123",
			MatchHeaders: []string{"Authorization"},
		},
		Rules: []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")
	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestInject_ConfigErrors(t *testing.T) {
	tests := []struct {
		name   string
		cfg    secretsConfig
		errMsg string
	}{
		{
			name: "both inject and replace",
			cfg: secretsConfig{Secrets: []secretEntry{{
				Source:  envSource("OPENAI_API_KEY"),
				Inject:  &injectConfig{Header: "Authorization"},
				Replace: &replaceConfig{ProxyValue: "tok"},
				Rules:   []hostmatch.RuleConfig{{Host: "example.com"}},
			}}},
			errMsg: "cannot specify both inject and replace",
		},
		{
			name: "inject with both header and query_param",
			cfg: secretsConfig{Secrets: []secretEntry{{
				Source: envSource("OPENAI_API_KEY"),
				Inject: &injectConfig{Header: "Authorization", QueryParam: "key"},
				Rules:  []hostmatch.RuleConfig{{Host: "example.com"}},
			}}},
			errMsg: "cannot specify both header and query_param",
		},
		{
			name: "inject with neither header nor query_param",
			cfg: secretsConfig{Secrets: []secretEntry{{
				Source: envSource("OPENAI_API_KEY"),
				Inject: &injectConfig{},
				Rules:  []hostmatch.RuleConfig{{Host: "example.com"}},
			}}},
			errMsg: "must specify either header or query_param",
		},
		{
			name: "replace block with empty proxy_value",
			cfg: secretsConfig{Secrets: []secretEntry{{
				Source:  envSource("OPENAI_API_KEY"),
				Replace: &replaceConfig{ProxyValue: ""},
				Rules:   []hostmatch.RuleConfig{{Host: "example.com"}},
			}}},
			errMsg: "replace.proxy_value is required",
		},
		{
			name: "legacy fields with replace block",
			cfg: secretsConfig{Secrets: []secretEntry{{
				Source:     envSource("OPENAI_API_KEY"),
				ProxyValue: "tok",
				Replace:    &replaceConfig{ProxyValue: "tok"},
				Rules:      []hostmatch.RuleConfig{{Host: "example.com"}},
			}}},
			errMsg: "cannot use both top-level proxy_value/match_headers and replace block",
		},
		{
			name: "legacy fields with inject block",
			cfg: secretsConfig{Secrets: []secretEntry{{
				Source:     envSource("OPENAI_API_KEY"),
				ProxyValue: "tok",
				Inject:     &injectConfig{Header: "Authorization"},
				Rules:      []hostmatch.RuleConfig{{Host: "example.com"}},
			}}},
			errMsg: "cannot use both top-level proxy_value/match_headers and inject block",
		},
		{
			name: "invalid formatter template",
			cfg: secretsConfig{Secrets: []secretEntry{{
				Source: envSource("OPENAI_API_KEY"),
				Inject: &injectConfig{Header: "Authorization", Formatter: "{{ .Invalid"},
				Rules:  []hostmatch.RuleConfig{{Host: "example.com"}},
			}}},
			errMsg: "parsing formatter template",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newFromConfig(tt.cfg, testRegistry())
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// --- Path mode tests ---

func telegramReq(path string) *http.Request {
	req := httptest.NewRequest("POST", "http://api.telegram.org"+path, nil)
	req.Host = "api.telegram.org"
	return req
}

func telegramReplaceEntry(opts ...func(*secretEntry)) secretEntry {
	e := secretEntry{
		Source: envSource("OPENAI_API_KEY"),
		Replace: &replaceConfig{
			ProxyValue:   "proxy-tg-token",
			MatchHeaders: []string{}, // disable header scanning
			MatchPath:    true,
		},
		Rules: []hostmatch.RuleConfig{{Host: "api.telegram.org"}},
	}
	for _, opt := range opts {
		opt(&e)
	}
	return e
}

func TestReplace_MatchPath(t *testing.T) {
	s := makeSecrets(t, []secretEntry{telegramReplaceEntry()})

	req := telegramReq("/botproxy-tg-token/sendMessage")
	doTransform(t, s, req)

	require.Equal(t, "/botsk-real-openai-key/sendMessage", req.URL.Path)
	require.Empty(t, req.URL.RawPath)
}

func TestReplace_MatchPath_NoMatchInPath(t *testing.T) {
	s := makeSecrets(t, []secretEntry{telegramReplaceEntry()})

	req := telegramReq("/sendMessage")
	doTransform(t, s, req)

	require.Equal(t, "/sendMessage", req.URL.Path)
}

func TestReplace_MatchPath_RequireRejectsWhenAbsent(t *testing.T) {
	s := makeSecrets(t, []secretEntry{telegramReplaceEntry(func(e *secretEntry) {
		e.Replace.Require = true
	})})

	req := telegramReq("/sendMessage")
	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
}

func TestReplace_MatchPath_ClearsRawPath(t *testing.T) {
	s := makeSecrets(t, []secretEntry{telegramReplaceEntry()})

	req := telegramReq("/botproxy-tg-token/sendMessage")
	// Simulate net/http populating an encoded RawPath alongside Path.
	req.URL.RawPath = "/botproxy-tg-token/sendMessage"
	doTransform(t, s, req)

	require.Equal(t, "/botsk-real-openai-key/sendMessage", req.URL.Path)
	require.Empty(t, req.URL.RawPath, "RawPath must be cleared so net/http re-encodes from Path")
}

func TestReplace_MatchPath_DefaultOff(t *testing.T) {
	// Without match_path, a proxy_value embedded in the path must be left alone.
	s := makeSecrets(t, []secretEntry{telegramReplaceEntry(func(e *secretEntry) {
		e.Replace.MatchPath = false
	})})

	req := telegramReq("/botproxy-tg-token/sendMessage")
	doTransform(t, s, req)

	require.Equal(t, "/botproxy-tg-token/sendMessage", req.URL.Path)
}

func TestInject_ConcurrentSafety(t *testing.T) {
	s := makeSecrets(t, []secretEntry{injectEntry()})

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := openaiReq("GET", "/v1/chat")
			doTransform(t, s, req)
			require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
		}()
	}
	wg.Wait()
}

// --- Lazy resolution + require-on-resolve-failure tests ---

func missingSecretRegistry() sourceBuilderRegistry {
	return sourceBuilderRegistry{
		"env": &fakeBuilder{secrets: map[string]string{}},
	}
}

func missingSecretEntry(opts ...func(*secretEntry)) secretEntry {
	e := secretEntry{
		Source:       envSource("MISSING"),
		ProxyValue:   "proxy-tok",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}
	for _, opt := range opts {
		opt(&e)
	}
	return e
}

func TestLazy_PipelineBuildsWhenSecretBackendUnreachable(t *testing.T) {
	cfg := secretsConfig{Secrets: []secretEntry{missingSecretEntry()}}
	s, err := newFromConfig(cfg, missingSecretRegistry())
	require.NoError(t, err, "pipeline must build even when the secret can't be fetched")
	require.NotNil(t, s)
}

func TestLazy_RequestSkipsUnavailableSecretWhenNotRequired(t *testing.T) {
	cfg := secretsConfig{Secrets: []secretEntry{missingSecretEntry()}}
	s, err := newFromConfig(cfg, missingSecretRegistry())
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-tok")

	tctx := &transform.TransformContext{}
	res, err := s.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	// Secret unavailable: header is left as-is.
	require.Equal(t, "Bearer proxy-tok", req.Header.Get("Authorization"))
}

func TestLazy_RequestRejectedWhenReplaceRequireAndSecretUnavailable(t *testing.T) {
	cfg := secretsConfig{Secrets: []secretEntry{missingSecretEntry(func(e *secretEntry) {
		e.Require = true
	})}}
	s, err := newFromConfig(cfg, missingSecretRegistry())
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-tok")

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
}

func TestLazy_RequestRejectedWhenInjectRequireAndSecretUnavailable(t *testing.T) {
	cfg := secretsConfig{Secrets: []secretEntry{{
		Source: envSource("MISSING"),
		Inject: &injectConfig{Header: "Authorization", Require: true},
		Rules:  []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}}}
	s, err := newFromConfig(cfg, missingSecretRegistry())
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
}

func TestLazy_InjectRequireFalseSkipsOnUnavailable(t *testing.T) {
	cfg := secretsConfig{Secrets: []secretEntry{{
		Source: envSource("MISSING"),
		Inject: &injectConfig{Header: "Authorization"},
		Rules:  []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}}}
	s, err := newFromConfig(cfg, missingSecretRegistry())
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	// Secret unavailable + require=false: header not set.
	require.Empty(t, req.Header.Get("Authorization"))
}

func TestLazy_MixedAvailableAndUnavailable(t *testing.T) {
	registry := sourceBuilderRegistry{
		"env": &fakeBuilder{secrets: map[string]string{
			"OPENAI_API_KEY": "sk-real-openai-key",
		}},
	}
	cfg := secretsConfig{Secrets: []secretEntry{
		{
			Source:       envSource("OPENAI_API_KEY"),
			ProxyValue:   "proxy-openai-abc123",
			MatchHeaders: []string{"Authorization"},
			Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		},
		{
			Source:       envSource("MISSING"),
			ProxyValue:   "proxy-other",
			MatchHeaders: []string{"X-Other"},
			Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		},
	}}
	s, err := newFromConfig(cfg, registry)
	require.NoError(t, err)

	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")
	req.Header.Set("X-Other", "proxy-other")

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	// Missing secret: X-Other untouched.
	require.Equal(t, "proxy-other", req.Header.Get("X-Other"))
}

func TestLazy_FailureCachedAcrossRequests(t *testing.T) {
	fr := &fakeBuilder{secrets: map[string]string{}}
	registry := sourceBuilderRegistry{"env": fr}

	cfg := secretsConfig{Secrets: []secretEntry{missingSecretEntry()}}
	s, err := newFromConfig(cfg, registry)
	require.NoError(t, err)

	for range 5 {
		req := httptest.NewRequest("GET", "http://api.example.com/v1", nil)
		req.Host = "api.example.com"
		req.Header.Set("Authorization", "Bearer proxy-tok")
		doTransform(t, s, req)
	}

	// Lazy fetch happened only once; subsequent requests served the cached error.
	fr.mu.Lock()
	defer fr.mu.Unlock()
	require.Equal(t, 1, fr.fetchCalls["MISSING"])
}
