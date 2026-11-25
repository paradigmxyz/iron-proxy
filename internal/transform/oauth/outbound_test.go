package oauth

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func TestTokenEndpoint_UsesOutboundDenyGuard(t *testing.T) {
	srv := newTokenServer(t, nil)
	guard, err := dnsguard.New(dnsguard.DefaultDenyCIDRs)
	require.NoError(t, err)
	transform.SetOutboundDialer((&net.Dialer{
		Timeout: 5 * time.Second,
		Control: guard.DialControl,
	}).DialContext)
	t.Cleanup(func() { transform.SetOutboundDialer(nil) })

	t.Run("token source refuses loopback", func(t *testing.T) {
		ts, err := clientCredentialsTokenSource(context.Background(), map[string]string{
			fieldClientID:     "client-id",
			fieldClientSecret: "client-secret",
		}, nil, srv.URL+"/token")
		require.NoError(t, err)

		_, err = ts.Token()
		require.Error(t, err)
		require.True(t, dnsguard.IsDenyError(err))
	})

	t.Run("transform rejects without contacting the endpoint", func(t *testing.T) {
		o := buildTransformWith(t, `
tokens:
  - grant: client_credentials
    require: true
    client_id: {type: env, var: CID}
    client_secret: {type: env, var: CSECRET}
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "api.example.com"
`, ccBuilder())

		req := newRequest(t, "GET", "https://api.example.com/v1/things")
		tctx := newContext()
		res, err := o.TransformRequest(context.Background(), tctx, req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionReject, res.Action)
		require.Equal(t, 502, res.Response.StatusCode)
		require.Empty(t, req.Header.Get("Authorization"))
		require.Equal(t, "token_unavailable", tctx.DrainAnnotations()["rejected"])
		require.Equal(t, 0, srv.Calls())
	})
}
