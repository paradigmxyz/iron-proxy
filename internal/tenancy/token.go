// Package tenancy implements tenancy mode: one proxy serving many tenants.
//
// A tenant presents a tenant token (an EdDSA/Ed25519 JWT minted by the
// control plane's API) as `Proxy-Authorization: Bearer <token>` on every
// CONNECT. The proxy verifies it, fetches that token's config from the
// control plane (authenticated with the proxy's own credential; the tenant
// token only selects whose config, so the token alone never yields one), and
// runs the tunnel's requests through the pipeline built from it. The proxy
// never interprets who a tenant is: the control plane decides what config a
// token gets.
package tenancy

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/ironsh/iron-proxy/internal/tenant"
)

// PublicKeysEnv names the environment variable holding the Ed25519 public
// keys (one or more SPKI PEM blocks) tenant tokens are verified with.
// Several keys allow rotation: a token verifies if any key accepts it.
const PublicKeysEnv = "IRON_TENANT_PUBLIC_KEYS"

// leeway tolerates clock skew between the token's minter and the proxy.
const leeway = 30 * time.Second

// maxLifetime bounds how far in the future a token may expire, so a leaked
// token cannot be minted to live forever.
const maxLifetime = 24 * time.Hour

// ParsePublicKeys parses one or more PEM-encoded Ed25519 public keys.
func ParsePublicKeys(data string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	rest := []byte(data)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("unexpected PEM block %q, want PUBLIC KEY", block.Type)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing public key: %w", err)
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is %T, want Ed25519", parsed)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("no PEM public keys found")
	}
	return keys, nil
}

// Verifier checks tenant tokens.
type Verifier struct {
	keys     []ed25519.PublicKey
	issuer   string
	audience string
	now      func() time.Time
}

// NewVerifier returns a Verifier accepting tokens signed by any of keys and
// carrying the given issuer and audience.
func NewVerifier(keys []ed25519.PublicKey, issuer, audience string) *Verifier {
	return &Verifier{keys: keys, issuer: issuer, audience: audience, now: time.Now}
}

type header struct {
	Alg string `json:"alg"`
}

type claims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"`
	Exp *float64        `json:"exp"`
	Nbf *float64        `json:"nbf"`
	Iat *float64        `json:"iat"`
	Jti string          `json:"jti"`
}

// errInvalid is returned for every malformed or rejected token. The reason
// is kept out of client responses; it never contains the token.
var errInvalid = errors.New("invalid tenant token")

// Verify checks raw's signature, issuer, audience and validity window, and
// returns the verified token.
func (v *Verifier) Verify(raw string) (*tenant.Token, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a JWT", errInvalid)
	}
	var h header
	if err := decodeSegment(parts[0], &h); err != nil {
		return nil, fmt.Errorf("%w: header: %v", errInvalid, err)
	}
	if h.Alg != "EdDSA" {
		return nil, fmt.Errorf("%w: alg %q, want EdDSA", errInvalid, h.Alg)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: malformed signature", errInvalid)
	}
	signed := []byte(parts[0] + "." + parts[1])
	verified := false
	for _, key := range v.keys {
		if ed25519.Verify(key, signed, signature) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("%w: signature", errInvalid)
	}

	var c claims
	if err := decodeSegment(parts[1], &c); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", errInvalid, err)
	}
	now := v.now()
	switch {
	case c.Iss != v.issuer:
		return nil, fmt.Errorf("%w: issuer", errInvalid)
	case !audienceContains(c.Aud, v.audience):
		return nil, fmt.Errorf("%w: audience", errInvalid)
	case c.Sub == "":
		return nil, fmt.Errorf("%w: no subject", errInvalid)
	case c.Exp == nil:
		return nil, fmt.Errorf("%w: no expiry", errInvalid)
	}
	for _, claim := range []*float64{c.Exp, c.Nbf, c.Iat} {
		if claim != nil && (math.IsNaN(*claim) || math.IsInf(*claim, 0) || *claim < 0 || *claim > maxUnixSeconds) {
			return nil, fmt.Errorf("%w: time claim out of range", errInvalid)
		}
	}
	expiresAt := unixTime(*c.Exp)
	if !now.Before(expiresAt.Add(leeway)) {
		return nil, fmt.Errorf("%w: expired", errInvalid)
	}
	if expiresAt.After(now.Add(maxLifetime + leeway)) {
		return nil, fmt.Errorf("%w: lifetime exceeds %s", errInvalid, maxLifetime)
	}
	if c.Nbf != nil && now.Add(leeway).Before(unixTime(*c.Nbf)) {
		return nil, fmt.Errorf("%w: not yet valid", errInvalid)
	}
	if c.Iat != nil && now.Add(leeway).Before(unixTime(*c.Iat)) {
		return nil, fmt.Errorf("%w: issued in the future", errInvalid)
	}
	return &tenant.Token{
		Raw:       raw,
		Subject:   c.Sub,
		ID:        c.Jti,
		ExpiresAt: expiresAt.Add(leeway),
	}, nil
}

func decodeSegment(segment string, into any) error {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return errors.New("not base64url")
	}
	if err := json.Unmarshal(data, into); err != nil {
		return errors.New("not a JSON object")
	}
	return nil
}

// audienceContains accepts the JWT `aud` claim as a string or an array.
func audienceContains(raw json.RawMessage, audience string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == audience
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == audience {
				return true
			}
		}
	}
	return false
}

// maxUnixSeconds keeps time claims well inside int64 nanoseconds.
const maxUnixSeconds = 1 << 40

func unixTime(seconds float64) time.Time {
	whole := int64(seconds)
	return time.Unix(whole, int64((seconds-float64(whole))*1e9))
}

// BearerToken returns the token in a `Bearer` Proxy-Authorization value.
func BearerToken(value string) (string, bool) {
	scheme, token, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}
