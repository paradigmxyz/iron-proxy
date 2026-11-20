package secrets

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/stretchr/testify/require"
)

func FuzzAlternativeCredentialHeaders(f *testing.F) {
	for _, value := range []string{"a", "b", "Bearer a", "bearer b", "BEARER a", "", "Bearer ", "Bearer  a", "Bearer a-suffix", "Basic YQ==", "Bearer upstream-secret-a"} {
		f.Add(value, "", false)
	}
	f.Add("Bearer a", "Bearer b", true)
	f.Add("Bearer a", "Bearer a", true)
	f.Add("a", "Bearer a", true)
	f.Add("Bearer a", "", true)
	f.Fuzz(func(t *testing.T, first, second string, multiple bool) {
		builder := &fakeBuilder{secrets: map[string]string{"A": "upstream-secret-a", "B": "upstream-secret-b"}}
		s, err := newFromConfig(secretsConfig{Secrets: []secretEntry{
			selectionEntry("A", "a", "provider-account", "Authorization"),
			selectionEntry("B", "b", "provider-account", "Authorization"),
		}}, sourceBuilderRegistry{"env": builder})
		require.NoError(t, err)
		req := openaiReq("POST", "/v1/responses")
		req.Header.Add("Authorization", first)
		if multiple {
			req.Header.Add("Authorization", second)
		}
		before := req.Header.Clone()
		var account string
		valid := true
		var expected []string
		for _, value := range before.Values("Authorization") {
			marker, prefix := value, ""
			if scheme, token, ok := strings.Cut(value, " "); ok && strings.EqualFold(scheme, "Bearer") {
				marker, prefix = token, scheme+" "
			}
			if (marker != "a" && marker != "b") || (account != "" && marker != account) {
				valid = false
			}
			account = marker
			expected = append(expected, prefix+"upstream-secret-"+marker)
		}
		tctx := &transform.TransformContext{}
		result, err := s.TransformRequest(context.Background(), tctx, req)
		require.NoError(t, err)
		if valid {
			require.Equal(t, transform.ActionContinue, result.Action)
			require.Equal(t, expected, req.Header.Values("Authorization"))
			require.Equal(t, map[string]int{strings.ToUpper(account): 1}, builder.fetchCalls)
		} else {
			require.Equal(t, transform.ActionReject, result.Action)
			require.Equal(t, before, req.Header)
			require.Empty(t, builder.fetchCalls)
		}
		audit, err := json.Marshal(tctx.DrainAnnotations())
		require.NoError(t, err)
		require.NotContains(t, string(audit), "upstream-secret-a")
		require.NotContains(t, string(audit), "upstream-secret-b")
	})
}
