package grpc

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	transformv1 "github.com/ironsh/iron-proxy/gen/transform/v1"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// Both RPCs must carry the tunnel's CONNECT credential to the server, and it
// must not leak into the http.Request that is forwarded upstream.
func TestTunnelCredential_RePresentedOnEachRPC(t *testing.T) {
	srv := &fakeServer{
		reqAction:  transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE,
		respAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE,
	}
	gt := newTestTransform(t, "authz", startFakeServer(t, srv), false, false)

	tctx := &transform.TransformContext{
		Tunnel: &transform.TunnelInfo{Target: "example.com:443", Credential: "Basic dXNlcjpwYXNz"},
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	require.NoError(t, err)
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody}

	cases := []struct {
		name string
		call func() error
		sent func() *transformv1.HttpRequest
	}{
		{"TransformRequest", func() error {
			_, err := gt.TransformRequest(context.Background(), tctx, req)
			return err
		}, func() *transformv1.HttpRequest { return srv.lastReqProto.GetRequest() }},
		{"TransformResponse", func() error {
			_, err := gt.TransformResponse(context.Background(), tctx, req, resp)
			return err
		}, func() *transformv1.HttpRequest { return srv.lastRespProto.GetRequest() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, tc.call())
			require.Equal(t, []string{"Basic dXNlcjpwYXNz"}, tc.sent().GetHeaders()["Proxy-Authorization"].GetValues())
			require.Empty(t, req.Header.Get("Proxy-Authorization"))
		})
	}
}

func TestApplyTunnelCredential(t *testing.T) {
	cases := []struct {
		name string
		tctx *transform.TransformContext
		pb   *transformv1.HttpRequest
		want []string
	}{
		{"nil context", nil, &transformv1.HttpRequest{}, nil},
		{"no tunnel", &transform.TransformContext{}, &transformv1.HttpRequest{}, nil},
		{"empty credential", &transform.TransformContext{Tunnel: &transform.TunnelInfo{Target: "example.com:443"}},
			&transformv1.HttpRequest{}, nil},
		{"sets header", &transform.TransformContext{Tunnel: &transform.TunnelInfo{Credential: "Bearer tunnel"}},
			&transformv1.HttpRequest{}, []string{"Bearer tunnel"}},
		// The tunnel's credential is the one the server validated at CONNECT;
		// a client-supplied inner header must not replace it.
		{"overrides inner header", &transform.TransformContext{Tunnel: &transform.TunnelInfo{Credential: "Bearer tunnel"}},
			&transformv1.HttpRequest{Headers: map[string]*transformv1.HeaderValues{
				"Proxy-Authorization": {Values: []string{"Bearer someone-else"}},
			}}, []string{"Bearer tunnel"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			applyTunnelCredential(tc.pb, tc.tctx)
			require.Equal(t, tc.want, tc.pb.GetHeaders()["Proxy-Authorization"].GetValues())
		})
	}
}
