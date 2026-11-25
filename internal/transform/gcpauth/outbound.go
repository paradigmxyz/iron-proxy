package gcpauth

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// withOutboundHTTPClient carries the installed outbound dialer on ctx for
// oauth2/google token exchanges. It leaves ctx untouched when no dialer is
// installed, preserving the default client behavior.
func withOutboundHTTPClient(ctx context.Context) context.Context {
	if transform.OutboundDialer() == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, transform.NewOutboundClient())
}
