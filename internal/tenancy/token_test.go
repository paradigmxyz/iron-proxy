package tenancy

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testIssuer   = "iron-control-plane"
	testAudience = "iron-proxy"
)

var testEpoch = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

func newTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func pemPublicKey(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func signJWTWithAlg(t *testing.T, priv ed25519.PrivateKey, alg string, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	require.NoError(t, err)
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := header + "." + payload
	signature := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signJWT(t *testing.T, priv ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	return signJWTWithAlg(t, priv, "EdDSA", claims)
}

func tamperClaims(t *testing.T, raw string, mutate func(map[string]any)) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3)
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var c map[string]any
	require.NoError(t, json.Unmarshal(data, &c))
	mutate(c)
	payload, err := json.Marshal(c)
	require.NoError(t, err)
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	return strings.Join(parts, ".")
}

func withSignature(t *testing.T, raw, signature string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3)
	parts[2] = signature
	return strings.Join(parts, ".")
}

func TestParsePublicKeys(t *testing.T) {
	t.Parallel()
	pub1, _ := newTestKey(t)
	pub2, _ := newTestKey(t)
	pem1 := pemPublicKey(t, pub1)
	pem2 := pemPublicKey(t, pub2)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER}))
	wrongTypePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ecDER}))
	badPKIXPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a key")}))

	tests := []struct {
		name    string
		data    string
		want    []ed25519.PublicKey
		wantErr string
	}{
		{name: "one key", data: pem1, want: []ed25519.PublicKey{pub1}},
		{name: "two keys", data: pem1 + pem2, want: []ed25519.PublicKey{pub1, pub2}},
		{name: "non-ed25519 key", data: ecPEM, wantErr: "want Ed25519"},
		{name: "wrong pem type", data: wrongTypePEM, wantErr: "unexpected PEM block"},
		{name: "invalid pkix", data: badPKIXPEM, wantErr: "parsing public key"},
		{name: "empty", data: "", wantErr: "no PEM public keys found"},
		{name: "not pem", data: "hello", wantErr: "no PEM public keys found"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParsePublicKeys(tc.data)
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestVerifierVerify(t *testing.T) {
	t.Parallel()
	pub1, priv1 := newTestKey(t)
	pub2, priv2 := newTestKey(t)
	_, unlisted := newTestKey(t)
	now := testEpoch

	base := func() map[string]any {
		return map[string]any{
			"iss": testIssuer,
			"sub": "tenant-a",
			"aud": testAudience,
			"exp": float64(now.Add(time.Hour).Unix()),
			"jti": "jti-1",
		}
	}

	tests := []struct {
		name        string
		keys        []ed25519.PublicKey
		raw         func(*testing.T) string
		wantSubject string
		wantErr     bool
	}{
		{
			name: "valid string audience",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				return signJWT(t, priv1, base())
			},
			wantSubject: "tenant-a",
		},
		{
			name: "valid array audience",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				c := base()
				c["aud"] = []string{"another-service", testAudience}
				return signJWT(t, priv1, c)
			},
			wantSubject: "tenant-a",
		},
		{
			name: "second of two keys accepted",
			keys: []ed25519.PublicKey{pub1, pub2},
			raw: func(t *testing.T) string {
				return signJWT(t, priv2, base())
			},
			wantSubject: "tenant-a",
		},
		{
			name: "wrong issuer",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				c := base()
				c["iss"] = "someone-else"
				return signJWT(t, priv1, c)
			},
			wantErr: true,
		},
		{
			name: "wrong audience",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				c := base()
				c["aud"] = "another-service"
				return signJWT(t, priv1, c)
			},
			wantErr: true,
		},
		{
			name: "missing subject",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				c := base()
				delete(c, "sub")
				return signJWT(t, priv1, c)
			},
			wantErr: true,
		},
		{
			name: "missing expiry",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				c := base()
				delete(c, "exp")
				return signJWT(t, priv1, c)
			},
			wantErr: true,
		},
		{
			name: "expired beyond leeway",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				c := base()
				c["exp"] = float64(now.Add(-leeway - time.Second).Unix())
				return signJWT(t, priv1, c)
			},
			wantErr: true,
		},
		{
			name: "expired within leeway",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				c := base()
				c["exp"] = float64(now.Add(-leeway + time.Second).Unix())
				return signJWT(t, priv1, c)
			},
			wantSubject: "tenant-a",
		},
		{
			name: "not before in the future",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				c := base()
				c["nbf"] = float64(now.Add(leeway + time.Second).Unix())
				return signJWT(t, priv1, c)
			},
			wantErr: true,
		},
		{
			name: "not before within leeway",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				c := base()
				c["nbf"] = float64(now.Add(leeway - time.Second).Unix())
				return signJWT(t, priv1, c)
			},
			wantSubject: "tenant-a",
		},
		{
			name: "issued at in the future",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				c := base()
				c["iat"] = float64(now.Add(leeway + time.Second).Unix())
				return signJWT(t, priv1, c)
			},
			wantErr: true,
		},
		{
			name: "issued at within leeway",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				c := base()
				c["iat"] = float64(now.Add(leeway - time.Second).Unix())
				return signJWT(t, priv1, c)
			},
			wantSubject: "tenant-a",
		},
		{
			name: "alg none",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				return signJWTWithAlg(t, priv1, "none", base())
			},
			wantErr: true,
		},
		{
			name: "alg hs256",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				return signJWTWithAlg(t, priv1, "HS256", base())
			},
			wantErr: true,
		},
		{
			name: "tampered claims",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				return tamperClaims(t, signJWT(t, priv1, base()), func(c map[string]any) {
					c["sub"] = "tenant-b"
				})
			},
			wantErr: true,
		},
		{
			name: "signature from an unlisted key",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				return signJWT(t, unlisted, base())
			},
			wantErr: true,
		},
		{
			name: "malformed signature",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				return withSignature(t, signJWT(t, priv1, base()), "!!!")
			},
			wantErr: true,
		},
		{
			name: "not a jwt",
			keys: []ed25519.PublicKey{pub1},
			raw: func(t *testing.T) string {
				return "a.b"
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := NewVerifier(tc.keys, testIssuer, testAudience)
			v.now = func() time.Time { return now }
			raw := tc.raw(t)

			got, err := v.Verify(raw)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, errInvalid)
				require.Nil(t, got)
				require.NotContains(t, err.Error(), raw)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, raw, got.Raw)
			require.Equal(t, tc.wantSubject, got.Subject)
			require.Equal(t, "jti-1", got.ID)
		})
	}
}

func TestBearerToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		value  string
		want   string
		wantOK bool
	}{
		{name: "bearer", value: "Bearer token-a", want: "token-a", wantOK: true},
		{name: "lowercase scheme", value: "bearer token-a", want: "token-a", wantOK: true},
		{name: "trims token", value: "Bearer   token-a  ", want: "token-a", wantOK: true},
		{name: "wrong scheme", value: "Basic token-a"},
		{name: "empty", value: ""},
		{name: "no token", value: "Bearer"},
		{name: "blank token", value: "Bearer   "},
		{name: "no scheme", value: "token-a"},
		{name: "tab separator", value: "Bearer\ttoken-a"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := BearerToken(tc.value)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.want, got)
		})
	}
}
