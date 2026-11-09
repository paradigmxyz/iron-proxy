package secrets

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	turnkeycrypto "github.com/tkhq/go-sdk/crypto"
	turnkey "github.com/tkhq/go-sdk/v2"

	"github.com/ironsh/iron-proxy/internal/transform"
)

func signedTurnkeyTestExport(t *testing.T, key *ecdsa.PrivateKey, target, org string, plaintext []byte, tamper bool) string {
	t.Helper()
	bundle, err := signTurnkeyTestExport(key, target, org, plaintext, tamper)
	require.NoError(t, err)
	return bundle
}

// signTurnkeyTestExport builds an export bundle signed by a test-only Signer key.
func signTurnkeyTestExport(key *ecdsa.PrivateKey, target, org string, plaintext []byte, tamper bool) (string, error) {
	public, err := hex.DecodeString(target)
	if err != nil {
		return "", err
	}
	kemPublic, err := turnkeycrypto.KemID.Scheme().UnmarshalBinaryPublicKey(public)
	if err != nil {
		return "", err
	}
	ciphertext, encapped, err := turnkeycrypto.HPKEEncrypt(&kemPublic, plaintext)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(turnkeycrypto.ServerSendData{EncappedPublic: encapped, Ciphertext: ciphertext, OrganizationID: org})
	if err != nil {
		return "", err
	}
	signature, err := turnkeycrypto.P256Sign(key, data)
	if err != nil {
		return "", err
	}
	if tamper {
		signature[0] ^= 1
	}
	quorum, err := key.PublicKey.ECDH()
	if err != nil {
		return "", err
	}
	bundle, err := json.Marshal(turnkeycrypto.ServerTargetMsgV1{Version: "v1.0.0", Data: data, DataSignature: signature, EnclaveQuorumPublic: quorum.Bytes()})
	return string(bundle), err
}

// Covers the actual source and transform, SDK stamp/retry, Signer verification,
// organization binding, HPKE decryption and json_key extraction without live keys.
func TestTurnkeySourceSDKExportThroughTransform(t *testing.T) {
	const org = "11111111-1111-4111-8111-111111111111"
	const secret = "22222222-2222-4222-8222-222222222222"
	const credential = "synthetic-upstream-credential"
	cases := []struct {
		name      string
		wantCalls int
		accepted  bool
	}{
		{"valid export", 1, true}, {"transient server failure then export", 2, true},
		{"wrong organization", 1, false}, {"invalid signature", 1, false},
		{"wrong recipient", 1, false}, {"malformed bundle", 1, false},
		{"approval required", 1, false}, {"activity rejected", 1, false}, {"permission denied", 1, false},
		{"missing json field", 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEST_TURNKEY_INTEGRATION_KEY", strings.Repeat("0", 63)+"1")
			signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			var calls atomic.Int32
			var firstBody []byte
			var firstStamp string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				call := calls.Add(1)
				require.Equal(t, "/public/v1/submit/export_secrets", r.URL.Path)
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.NotEmpty(t, r.Header.Get("X-Stamp"))
				if call == 1 {
					firstBody = body
					firstStamp = r.Header.Get("X-Stamp")
				} else {
					require.Equal(t, firstBody, body)
					require.Equal(t, firstStamp, r.Header.Get("X-Stamp"))
				}
				if tc.name == "transient server failure then export" && call == 1 {
					w.WriteHeader(503)
					return
				}
				if tc.name == "permission denied" {
					w.WriteHeader(403)
					_, _ = io.WriteString(w, `{"message":"sensitive-backend-detail"}`) // Mock response may be abandoned by the client.
					return
				}
				var request struct {
					OrganizationID string                      `json:"organizationId"`
					Parameters     turnkey.ExportSecretsIntent `json:"parameters"`
				}
				require.NoError(t, json.Unmarshal(body, &request))
				require.Equal(t, org, request.OrganizationID)
				require.Len(t, request.Parameters.Secrets, 1)
				param := request.Parameters.Secrets[0]
				require.Equal(t, secret, param.SecretID)
				status := turnkey.ActivityStatusCompleted
				exportOrg := org
				if tc.name == "wrong organization" {
					exportOrg = "other-org"
				}
				target := param.TargetPublicKey
				if tc.name == "wrong recipient" {
					var err error
					target, _, err = turnkeycrypto.GenerateEncryptionKeyPair()
					require.NoError(t, err)
				}
				plaintext := []byte(`{"api_key":"` + credential + `"}`)
				if tc.name == "missing json field" {
					plaintext = []byte(`{"other":"` + credential + `"}`)
				}
				bundle := signedTurnkeyTestExport(t, signer, target, exportOrg, plaintext, tc.name == "invalid signature")
				if tc.name == "malformed bundle" {
					bundle = "sensitive-backend-detail"
				}
				if tc.name == "approval required" {
					status = turnkey.ActivityStatusConsensusNeeded
				}
				if tc.name == "activity rejected" {
					status = turnkey.ActivityStatusRejected
				}
				response := map[string]any{"activity": map[string]any{
					"id": "33333333-3333-4333-8333-333333333333", "status": status,
					"result": map[string]any{"exportSecretsResult": turnkey.ExportSecretsResult{SecretPayloads: []string{bundle}}},
				}}
				if tc.name == "approval required" || tc.name == "activity rejected" {
					delete(response["activity"].(map[string]any), "result")
				}
				require.NoError(t, json.NewEncoder(w).Encode(response))
			}))
			defer server.Close()
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			cache := &turnkeyClientCache{newClient: func(org, env string) (turnkeyClient, error) {
				return newTurnkeySDKClient(org, env, server.Client().Transport, turnkey.WithBaseURL(server.URL))
			}}
			// Test-only trust override: production always uses the SDK's production Signer.
			builder := &turnkeyBuilder{clientFor: cache.get, logger: logger, signerKey: &signer.PublicKey}
			var config secretsConfig
			node := yamlNode(t, map[string]any{"secrets": []any{map[string]any{
				"source":  map[string]any{"type": "turnkey", "organization_id": org, "secret_id": secret, "api_private_key_env": "TEST_TURNKEY_INTEGRATION_KEY", "json_key": "api_key"},
				"replace": map[string]any{"proxy_value": "agent-placeholder", "match_headers": []string{"Authorization"}, "require": true},
				"rules":   []any{map[string]any{"host": "provider.test"}},
			}}})
			require.NoError(t, node.Decode(&config))
			tr, err := newFromConfig(config, sourceBuilderRegistry{"turnkey": builder})
			require.NoError(t, err)
			require.Zero(t, calls.Load(), "configuration must not export")
			for range 2 {
				req := httptest.NewRequest("POST", "https://provider.test/v1/chat/completions", nil)
				req.Header.Set("Authorization", "Bearer agent-placeholder")
				result, err := tr.TransformRequest(context.Background(), &transform.TransformContext{}, req)
				require.NoError(t, err)
				if tc.accepted {
					require.Equal(t, transform.ActionContinue, result.Action)
					require.Equal(t, "Bearer "+credential, req.Header.Get("Authorization"))
				} else {
					require.Equal(t, transform.ActionReject, result.Action)
					require.Equal(t, "Bearer agent-placeholder", req.Header.Get("Authorization"))
				}
			}
			require.Equal(t, int32(tc.wantCalls), calls.Load(), "successes and failures must be cached")
			require.NotContains(t, logs.String(), credential)
			require.NotContains(t, logs.String(), "sensitive-backend-detail")
		})
	}
}

// Covers the approval path with the real SDK: one export activity, then reads
// of that activity until it completes, decrypted with the original recipient key.
func TestTurnkeySourceResumesApprovedExport(t *testing.T) {
	const org = "11111111-1111-4111-8111-111111111111"
	const secret = "22222222-2222-4222-8222-222222222222"
	const activityID = "33333333-3333-4333-8333-333333333333"
	t.Setenv("TEST_TURNKEY_INTEGRATION_KEY", strings.Repeat("0", 63)+"1")
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var exports, reads atomic.Int32
	var approved atomic.Bool
	var target string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		activity := map[string]any{"id": activityID, "status": turnkey.ActivityStatusConsensusNeeded}
		switch r.URL.Path {
		case "/public/v1/submit/export_secrets":
			exports.Add(1)
			var request struct {
				Parameters turnkey.ExportSecretsIntent `json:"parameters"`
			}
			require.NoError(t, json.Unmarshal(body, &request))
			target = request.Parameters.Secrets[0].TargetPublicKey
		case "/public/v1/query/get_activity":
			reads.Add(1)
			var request turnkey.GetActivityRequest
			require.NoError(t, json.Unmarshal(body, &request))
			require.Equal(t, activityID, request.ActivityID)
			require.Equal(t, org, request.OrganizationID)
			if approved.Load() {
				activity["status"] = turnkey.ActivityStatusCompleted
				activity["result"] = map[string]any{"exportSecretsResult": turnkey.ExportSecretsResult{
					SecretPayloads: []string{signedTurnkeyTestExport(t, signer, target, org, []byte("synthetic-approved-credential"), false)},
				}}
			}
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"activity": activity}))
	}))
	defer server.Close()
	var logs bytes.Buffer
	builder := &turnkeyBuilder{
		logger:    slog.New(slog.NewJSONHandler(&logs, nil)),
		signerKey: &signer.PublicKey,
		clientFor: func(org, env string) (turnkeyClient, error) {
			return newTurnkeySDKClient(org, env, server.Client().Transport, turnkey.WithBaseURL(server.URL))
		},
	}
	source, err := builder.Build(yamlNode(t, map[string]string{
		"organization_id": org, "secret_id": secret, "api_private_key_env": "TEST_TURNKEY_INTEGRATION_KEY",
	}))
	require.NoError(t, err)
	now := time.Now()
	source.(*cachedValue).now = func() time.Time { return now }
	for range 3 {
		_, err := source.Get(context.Background())
		require.EqualError(t, err, "turnkey secret export failed (approval_required, activity "+activityID+")")
		now = now.Add(2 * time.Minute)
	}
	require.Equal(t, int32(1), exports.Load(), "retries must not submit new exports")
	require.Equal(t, int32(2), reads.Load())
	approved.Store(true)
	value, err := source.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "synthetic-approved-credential", value)
	require.Equal(t, int32(1), exports.Load())
	require.NotContains(t, logs.String(), "synthetic-approved-credential")
}
