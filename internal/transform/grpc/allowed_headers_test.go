package grpc

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	transformv1 "github.com/ironsh/iron-proxy/gen/transform/v1"
)

func headerNames(h map[string]*transformv1.HeaderValues) []string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	return names
}

func TestAllowedHeaders_FiltersWhatReachesServer(t *testing.T) {
	srv := &fakeServer{
		reqAction:  transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE,
		respAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE,
	}
	gt, err := newGRPCTransform(grpcConfig{
		Name:           "policy",
		Target:         startFakeServer(t, srv),
		AllowedHeaders: []string{"user-agent", "/^X-Trace-.*$/"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gt.Close() })

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/messages", nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "client/1.0")
	req.Header.Set("X-Trace-Id", "abc")
	req.Header.Set("Authorization", "Bearer upstream-secret")
	req.Header.Set("Cookie", "session=1")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}, "Set-Cookie": {"s=2"}, "X-Trace-Id": {"abc"}},
		Body:       http.NoBody,
	}

	_, err = gt.TransformRequest(context.Background(), testContext(), req)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"User-Agent", "X-Trace-Id"}, headerNames(srv.lastReqProto.GetRequest().GetHeaders()))

	_, err = gt.TransformResponse(context.Background(), testContext(), req, resp)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"User-Agent", "X-Trace-Id"}, headerNames(srv.lastRespProto.GetRequest().GetHeaders()))
	require.ElementsMatch(t, []string{"X-Trace-Id"}, headerNames(srv.lastRespProto.GetResponse().GetHeaders()))

	// Only the proto is filtered; the request that goes upstream keeps its headers.
	require.Equal(t, "Bearer upstream-secret", req.Header.Get("Authorization"))
	require.Equal(t, "session=1", req.Header.Get("Cookie"))
}

func TestAllowedHeaders_EmptyForwardsAll(t *testing.T) {
	srv := &fakeServer{reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	gt := newTestTransform(t, "all", startFakeServer(t, srv), false, false)

	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer x")
	req.Header.Set("Cookie", "a=b")

	_, err = gt.TransformRequest(context.Background(), testContext(), req)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"Authorization", "Cookie"}, headerNames(srv.lastReqProto.GetRequest().GetHeaders()))
}

func TestAllowedHeaders_InvalidRegex(t *testing.T) {
	srv := &fakeServer{reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	_, err := newGRPCTransform(grpcConfig{
		Name:           "bad",
		Target:         startFakeServer(t, srv),
		AllowedHeaders: []string{"/[/"},
	})
	require.ErrorContains(t, err, "invalid allowed_headers regex")
}

func TestFactory_ParsesAllowedHeaders(t *testing.T) {
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte("name: t\ntarget: localhost:9500\nallowed_headers: [Content-Type, /^X-Trace-.*$/]\n"), &node))
	tr, err := factory(node, nil)
	require.NoError(t, err)
	gt := tr.(*GRPCTransform)
	t.Cleanup(func() { _ = gt.Close() })
	require.Len(t, gt.allowedHeaders, 2)
	require.True(t, headerAllowed(gt.allowedHeaders, "content-type"))
	require.True(t, headerAllowed(gt.allowedHeaders, "x-trace-id"))
	require.False(t, headerAllowed(gt.allowedHeaders, "authorization"))
}
