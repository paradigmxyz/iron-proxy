package secrets

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRestrictTenantSources_Secrets(t *testing.T) {
	tests := []struct {
		name        string
		secrets     string
		want        string
		wantReasons []string
	}{
		{
			name: "keeps only tenant source types",
			secrets: `[
				{"source":{"type":"env","var":"A"},"inject":{"header":"Authorization"},"rules":[{"host":"a.example"}]},
				{"source":{"type":"control_plane","value":"v"},"inject":{"header":"Authorization"},"rules":[{"host":"b.example"}]},
				{"source":{"type":"file","path":"/run/secret"},"inject":{"header":"Authorization"},"rules":[{"host":"c.example"}]},
				{"source":{"type":"vault_kv","path":"secret/value"},"inject":{"header":"Authorization"},"rules":[{"host":"d.example"}]},
				{"source":{"type":"tenant_token"},"inject":{"header":"Authorization"},"rules":[{"host":"e.example"}]}
			]`,
			want: `[
				{"source":{"type":"control_plane","value":"v"},"inject":{"header":"Authorization"},"rules":[{"host":"b.example"}]},
				{"source":{"type":"tenant_token"},"inject":{"header":"Authorization"},"rules":[{"host":"e.example"}]}
			]`,
			wantReasons: []string{
				`secrets[0].source uses disallowed source type "env"`,
				`secrets[2].source uses disallowed source type "file"`,
				`secrets[3].source uses disallowed source type "vault_kv"`,
			},
		},
		{
			name:        "keeps sources that are already tenant safe",
			secrets:     `[{"source":{"type":"aws_sm","secret_id":"arn:aws:sm:test"}}]`,
			want:        `[{"source":{"type":"aws_sm","secret_id":"arn:aws:sm:test"}}]`,
			wantReasons: nil,
		},
		{
			name:        "drops every entry when all use env or file",
			secrets:     `[{"source":{"type":"env","var":"A"}},{"source":{"type":"file","path":"/x"}}]`,
			want:        `[]`,
			wantReasons: []string{`secrets[0].source uses disallowed source type "env"`, `secrets[1].source uses disallowed source type "file"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, reasons, err := RestrictTenantSources(json.RawMessage(tt.secrets), nil)
			require.NoError(t, err)
			require.JSONEq(t, tt.want, string(got))
			require.Equal(t, tt.wantReasons, reasons)
		})
	}
}

func TestRestrictTenantSources_Transforms(t *testing.T) {
	tests := []struct {
		name        string
		transforms  string
		want        string
		wantReasons []string
	}{
		{
			name:       "drops hmac_sign with an env credential",
			transforms: `[{"name":"hmac_sign","config":{"credentials":{"secret":{"type":"env","var":"K"}},"rules":[{"host":"example.com"}]}}]`,
			want:       `[]`,
			wantReasons: []string{
				`transforms[0] (hmac_sign): config.credentials.secret uses disallowed source type "env"`,
			},
		},
		{
			name:       "drops hmac_sign with a file credential",
			transforms: `[{"name":"hmac_sign","config":{"credentials":{"passphrase":{"type":"file","path":"/run/pass"}},"rules":[{"host":"example.com"}]}}]`,
			want:       `[]`,
			wantReasons: []string{
				`transforms[0] (hmac_sign): config.credentials.passphrase uses disallowed source type "file"`,
			},
		},
		{
			name:       "drops aws_auth with an env access key",
			transforms: `[{"name":"aws_auth","config":{"access_key_id":{"type":"env","var":"AWS_ACCESS_KEY_ID"},"secret_access_key":{"type":"control_plane","value":"v"},"rules":[{"host":"example.com"}]}}]`,
			want:       `[]`,
			wantReasons: []string{
				`transforms[0] (aws_auth): config.access_key_id uses disallowed source type "env"`,
			},
		},
		{
			name:       "drops gcp_auth with an env keyfile",
			transforms: `[{"name":"gcp_auth","config":{"keyfile":{"type":"env","var":"GCP_KEYFILE"},"scopes":["https://www.googleapis.com/auth/cloud-platform"]}}]`,
			want:       `[]`,
			wantReasons: []string{
				`transforms[0] (gcp_auth): config.keyfile uses disallowed source type "env"`,
			},
		},
		{
			name:       "drops gcp_auth with keyfile_path",
			transforms: `[{"name":"gcp_auth","config":{"keyfile_path":"/etc/iron-proxy/gcp-sa.json","scopes":["https://www.googleapis.com/auth/cloud-platform"]}}]`,
			want:       `[]`,
			wantReasons: []string{
				`transforms[0] (gcp_auth): config sets keyfile_path`,
			},
		},
		{
			name:       "drops gcp_id_token with a file keyfile",
			transforms: `[{"name":"gcp_id_token","config":{"keyfile":{"type":"file","path":"/run/sa.json"},"audience":"https://svc.example","rules":[{"host":"svc.example"}]}}]`,
			want:       `[]`,
			wantReasons: []string{
				`transforms[0] (gcp_id_token): config.keyfile uses disallowed source type "file"`,
			},
		},
		{
			name: "oauth_token drops only the offending tokens entry",
			transforms: `[{"name":"oauth_token","config":{"tokens":[
				{"grant":"client_credentials","client_id":{"type":"env","var":"CLIENT_ID"},"client_secret":{"type":"control_plane","value":"v"},"rules":[{"host":"a.example"}]},
				{"grant":"refresh_token","refresh_token":{"type":"control_plane","value":"r"},"client_id":{"type":"control_plane","value":"c"},"rules":[{"host":"b.example"}]}
			]}}]`,
			want: `[{"name":"oauth_token","config":{"tokens":[
				{"grant":"refresh_token","refresh_token":{"type":"control_plane","value":"r"},"client_id":{"type":"control_plane","value":"c"},"rules":[{"host":"b.example"}]}
			]}}]`,
			wantReasons: []string{
				`transforms[0] (oauth_token): tokens[0].client_id uses disallowed source type "env"`,
			},
		},
		{
			name: "oauth_token drops the transform when every token is disallowed",
			transforms: `[{"name":"oauth_token","config":{"tokens":[
				{"grant":"client_credentials","client_id":{"type":"env","var":"CLIENT_ID"},"client_secret":{"type":"control_plane","value":"v"}},
				{"grant":"refresh_token","refresh_token":{"type":"env","var":"REFRESH_TOKEN"},"client_id":{"type":"control_plane","value":"c"}}
			]}}]`,
			want: `[]`,
			wantReasons: []string{
				`transforms[0] (oauth_token): tokens[0].client_id uses disallowed source type "env"`,
				`transforms[0] (oauth_token): tokens[1].refresh_token uses disallowed source type "env"`,
			},
		},
		{
			name:       "keeps oauth_token when all tokens are tenant safe",
			transforms: `[{"name":"oauth_token","config":{"tokens":[{"grant":"client_credentials","client_id":{"type":"control_plane","value":"c"},"client_secret":{"type":"control_plane","value":"s"}}]}}]`,
			want:       `[{"name":"oauth_token","config":{"tokens":[{"grant":"client_credentials","client_id":{"type":"control_plane","value":"c"},"client_secret":{"type":"control_plane","value":"s"}}]}}]`,
		},
		{
			name:        "drops transforms that are not credential transforms",
			transforms:  `[{"name":"allowlist","config":{"domains":["api.openai.com"]}},{"name":"grpc","config":{"target":"evil:443"}},{"name":"annotate","config":{"headers":["authorization"]}}]`,
			want:        `[]`,
			wantReasons: []string{`transforms[0] (allowlist): transform is not allowed for tenants`, `transforms[1] (grpc): transform is not allowed for tenants`, `transforms[2] (annotate): transform is not allowed for tenants`},
		},
		{
			// Any type a tenant may not use is refused, not only env and
			// file.
			name:        "drops transforms with any other typed object",
			transforms:  `[{"name":"hmac_sign","config":{"credentials":{"secret":{"type":"vault_kv","path":"p"}}}},{"name":"gcp_auth","config":{"keyfile":{"type":"anthropic"},"scopes":["s"]}}]`,
			want:        `[]`,
			wantReasons: []string{`transforms[0] (hmac_sign): config.credentials.secret uses disallowed source type "vault_kv"`, `transforms[1] (gcp_auth): config.keyfile uses disallowed source type "anthropic"`},
		},
		{
			name:       "keeps workload identity providers",
			transforms: `[{"name":"gcp_auth","config":{"credentials_provider":{"type":"workload_identity"},"scopes":["s"]}}]`,
			want:       `[{"name":"gcp_auth","config":{"credentials_provider":{"type":"workload_identity"},"scopes":["s"]}}]`,
		},
		{
			name: "keeps allowed transforms and drops disallowed ones",
			transforms: `[
				{"name":"allowlist","config":{"domains":["api.openai.com"]}},
				{"name":"gcp_auth","config":{"keyfile_path":"/etc/iron-proxy/gcp-sa.json"}},
				{"name":"oauth_token","config":{"tokens":[
					{"grant":"refresh_token","refresh_token":{"type":"file","path":"/run/rt"},"client_id":{"type":"control_plane","value":"c"}},
					{"grant":"refresh_token","refresh_token":{"type":"control_plane","value":"r"},"client_id":{"type":"control_plane","value":"c"}}
				]}}
			]`,
			want: `[
				{"name":"oauth_token","config":{"tokens":[
					{"grant":"refresh_token","refresh_token":{"type":"control_plane","value":"r"},"client_id":{"type":"control_plane","value":"c"}}
				]}}
			]`,
			wantReasons: []string{
				`transforms[0] (allowlist): transform is not allowed for tenants`,
				`transforms[1] (gcp_auth): config sets keyfile_path`,
				`transforms[2] (oauth_token): tokens[0].refresh_token uses disallowed source type "file"`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got, reasons, err := RestrictTenantSources(nil, json.RawMessage(tt.transforms))
			require.NoError(t, err)
			require.JSONEq(t, tt.want, string(got))
			require.Equal(t, tt.wantReasons, reasons)
		})
	}
}

func TestRestrictTenantSources_NilAndNull(t *testing.T) {
	secrets, transforms, reasons, err := RestrictTenantSources(nil, nil)
	require.NoError(t, err)
	require.Nil(t, secrets)
	require.Nil(t, transforms)
	require.Empty(t, reasons)

	secrets, transforms, reasons, err = RestrictTenantSources(json.RawMessage("null"), json.RawMessage("null"))
	require.NoError(t, err)
	require.Equal(t, json.RawMessage("null"), secrets)
	require.Equal(t, json.RawMessage("null"), transforms)
	require.Empty(t, reasons)
}

func TestRestrictTenantSources_InvalidJSON(t *testing.T) {
	_, _, _, err := RestrictTenantSources(json.RawMessage(`{bad`), nil)
	require.ErrorContains(t, err, "parsing secrets")

	_, _, _, err = RestrictTenantSources(nil, json.RawMessage(`{bad`))
	require.ErrorContains(t, err, "parsing transforms")
}

// Case-variant or duplicate keys must not let the check and the builder see
// different types: the check reads exact keys, and what is kept is re-encoded
// from what was checked.
func TestRestrictTenantSources_CaseVariantKeysCannotSmuggleATypePast(t *testing.T) {
	secrets := json.RawMessage(`[
		{"source":{"type":"env","Type":"aws_sm","var":"X"},"inject":{"header":"A"},"rules":[{"host":"a.example"}]},
		{"source":{"TYPE":"tenant_token","type":"file","path":"/ca.key"},"inject":{"header":"A"},"rules":[{"host":"a.example"}]},
		{"source":{"type":"aws_sm","Type":"env","secret_id":"s"},"inject":{"header":"A"},"rules":[{"host":"a.example"}]}
	]`)
	gotSecrets, _, reasons, err := RestrictTenantSources(secrets, nil)
	require.NoError(t, err)
	require.Len(t, reasons, 2)
	var kept []struct {
		Source map[string]any `json:"source"`
	}
	require.NoError(t, json.Unmarshal(gotSecrets, &kept))
	require.Len(t, kept, 1)
	// The kept entry's exact "type" is the one that was checked.
	require.Equal(t, "aws_sm", kept[0].Source["type"])
}
