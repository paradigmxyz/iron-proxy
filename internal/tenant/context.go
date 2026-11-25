// Package tenant carries a verified tenant token through a request's
// context, so transforms and secret sources can see which tenant a request
// belongs to in tenancy mode. Outside tenancy mode no token is present.
package tenant

import (
	"context"
	"time"
)

// Token is a verified tenant token.
type Token struct {
	// Raw is the token as presented. It is a credential: never log it.
	Raw string
	// Subject is the token's `sub` claim.
	Subject string
	// ID is the token's `jti` claim, if any.
	ID string
	// ExpiresAt is the token's `exp` claim.
	ExpiresAt time.Time
}

// Expired reports whether the token has expired at now.
func (t *Token) Expired(now time.Time) bool {
	return !now.Before(t.ExpiresAt)
}

type contextKey struct{}

// WithToken returns a copy of ctx carrying tok.
func WithToken(ctx context.Context, tok *Token) context.Context {
	return context.WithValue(ctx, contextKey{}, tok)
}

// FromContext returns the tenant token carried by ctx, if any.
func FromContext(ctx context.Context) (*Token, bool) {
	tok, ok := ctx.Value(contextKey{}).(*Token)
	return tok, ok && tok != nil
}
