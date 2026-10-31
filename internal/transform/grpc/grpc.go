// Package grpc implements a transform that delegates to an external gRPC TransformService server.
package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
	"gopkg.in/yaml.v3"

	transformv1 "github.com/ironsh/iron-proxy/gen/transform/v1"
	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("grpc", factory)
}

type grpcConfig struct {
	Name             string                 `yaml:"name"`
	Target           string                 `yaml:"target"`
	TLS              tlsConfig              `yaml:"tls"`
	SendRequestBody  bool                   `yaml:"send_request_body"`
	SendResponseBody bool                   `yaml:"send_response_body"`
	Rules            []hostmatch.RuleConfig `yaml:"rules"`
	Timeout          time.Duration          `yaml:"timeout"` // per-RPC deadline (default 15s)
}

const defaultTimeout = 15 * time.Second

type tlsConfig struct {
	Enabled bool   `yaml:"enabled"` // enable TLS (default false, meaning plaintext)
	CACert  string `yaml:"ca_cert"` // custom CA for server verification
	Cert    string `yaml:"cert"`    // client cert for mTLS
	Key     string `yaml:"key"`     // client key for mTLS
}

// GRPCTransform delegates to a single external gRPC TransformService server.
type GRPCTransform struct {
	name             string
	sendRequestBody  bool
	sendResponseBody bool
	rules            []hostmatch.Rule
	conn             *grpc.ClientConn
	client           transformv1.TransformServiceClient
	timeout          time.Duration
}

func factory(cfg yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var c grpcConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing grpc config: %w", err)
	}
	if c.Name == "" {
		return nil, fmt.Errorf("grpc transform: name is required")
	}
	if c.Target == "" {
		return nil, fmt.Errorf("grpc transform %q: target is required", c.Name)
	}
	return newGRPCTransform(c)
}

func buildTransportCredentials(cfg tlsConfig, name string) (grpc.DialOption, error) {
	if !cfg.Enabled {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}

	tlsCfg := &tls.Config{}

	if cfg.CACert != "" {
		caPEM, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("grpc transform %q: reading ca_cert: %w", name, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("grpc transform %q: ca_cert contains no valid certificates", name)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.Cert != "" || cfg.Key != "" {
		if cfg.Cert == "" || cfg.Key == "" {
			return nil, fmt.Errorf("grpc transform %q: both cert and key are required for mTLS", name)
		}
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("grpc transform %q: loading client cert/key: %w", name, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)), nil
}

func newGRPCTransform(cfg grpcConfig) (*GRPCTransform, error) {
	creds, err := buildTransportCredentials(cfg.TLS, cfg.Name)
	if err != nil {
		return nil, err
	}

	prefix := fmt.Sprintf("grpc transform %q", cfg.Name)
	rules, err := hostmatch.CompileRules(cfg.Rules, prefix)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(cfg.Target, creds)
	if err != nil {
		return nil, fmt.Errorf("grpc transform %q: %w", cfg.Name, err)
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return &GRPCTransform{
		name:             cfg.Name,
		sendRequestBody:  cfg.SendRequestBody,
		sendResponseBody: cfg.SendResponseBody,
		rules:            rules,
		conn:             conn,
		client:           transformv1.NewTransformServiceClient(conn),
		timeout:          timeout,
	}, nil
}

func (g *GRPCTransform) Name() string { return g.name }

func (g *GRPCTransform) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if len(g.rules) > 0 && !hostmatch.MatchAnyRule(g.rules, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	pbReq, err := httpRequestToProto(req, g.sendRequestBody)
	if err != nil {
		return nil, fmt.Errorf("grpc transform %q: marshaling request: %w", g.name, err)
	}

	callCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	resp, err := g.client.TransformRequest(callCtx, &transformv1.TransformRequestRequest{
		Context: transformContextToProto(tctx),
		Request: pbReq,
	})
	if err != nil {
		return nil, fmt.Errorf("grpc transform %q: TransformRequest: %w", g.name, err)
	}

	for k, v := range resp.GetAnnotations() {
		tctx.Annotate(k, v)
	}

	if resp.GetAction() == transformv1.TransformAction_TRANSFORM_ACTION_REJECT {
		result := &transform.TransformResult{Action: transform.ActionReject}
		if resp.GetResponse() != nil {
			result.Response = protoToHTTPResponse(resp.GetResponse(), req)
		}
		return result, nil
	}

	if resp.GetModifiedRequest() != nil {
		applyModifiedRequest(resp.GetModifiedRequest(), req)
	}

	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (g *GRPCTransform) TransformResponse(ctx context.Context, tctx *transform.TransformContext, req *http.Request, resp *http.Response) (*transform.TransformResult, error) {
	if len(g.rules) > 0 && !hostmatch.MatchAnyRule(g.rules, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	pbReq, err := httpRequestToProto(req, g.sendRequestBody)
	if err != nil {
		return nil, fmt.Errorf("grpc transform %q: marshaling request: %w", g.name, err)
	}
	pbResp, err := httpResponseToProto(resp, g.sendResponseBody)
	if err != nil {
		return nil, fmt.Errorf("grpc transform %q: marshaling response: %w", g.name, err)
	}

	callCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	grpcResp, err := g.client.TransformResponse(callCtx, &transformv1.TransformResponseRequest{
		Context:  transformContextToProto(tctx),
		Request:  pbReq,
		Response: pbResp,
	})
	if err != nil {
		return nil, fmt.Errorf("grpc transform %q: TransformResponse: %w", g.name, err)
	}

	for k, v := range grpcResp.GetAnnotations() {
		tctx.Annotate(k, v)
	}

	if grpcResp.GetAction() == transformv1.TransformAction_TRANSFORM_ACTION_REJECT {
		result := &transform.TransformResult{Action: transform.ActionReject}
		if grpcResp.GetModifiedResponse() != nil {
			result.Response = protoToHTTPResponse(grpcResp.GetModifiedResponse(), req)
		}
		return result, nil
	}

	if grpcResp.GetModifiedResponse() != nil {
		applyModifiedResponse(grpcResp.GetModifiedResponse(), resp)
	}

	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// Close shuts down the backend connection.
func (g *GRPCTransform) Close() error {
	return g.conn.Close()
}

// --- proto conversion helpers ---

func transformContextToProto(tctx *transform.TransformContext) *transformv1.TransformContext {
	pb := &transformv1.TransformContext{
		Sni: tctx.SNI,
	}
	if tctx.ClientCert != nil {
		pb.ClientCertDer = tctx.ClientCert.Raw
	}
	if tctx.Tunnel != nil {
		pb.Tunnel = &transformv1.TunnelInfo{
			Target:            tctx.Tunnel.Target,
			RequestTransforms: tunnelTransformsToProto(tctx.Tunnel.RequestTransforms),
		}
	}
	return pb
}

func tunnelTransformsToProto(traces []transform.TransformTrace) []*transformv1.TunnelRequestTransform {
	if len(traces) == 0 {
		return nil
	}
	out := make([]*transformv1.TunnelRequestTransform, 0, len(traces))
	for _, tr := range traces {
		out = append(out, &transformv1.TunnelRequestTransform{
			Name:        tr.Name,
			Annotations: annotationsToStruct(tr.Annotations),
		})
	}
	return out
}

// annotationsToStruct marshals an annotations map into a google.protobuf.Struct.
// Entries whose values can't be represented (e.g. arbitrary structs, channels)
// are dropped rather than failing the whole conversion.
func annotationsToStruct(annotations map[string]any) *structpb.Struct {
	if len(annotations) == 0 {
		return nil
	}
	fields := make(map[string]*structpb.Value, len(annotations))
	for k, v := range annotations {
		val, err := structpb.NewValue(v)
		if err != nil {
			continue
		}
		fields[k] = val
	}
	if len(fields) == 0 {
		return nil
	}
	return &structpb.Struct{Fields: fields}
}

func httpRequestToProto(req *http.Request, sendBody bool) (*transformv1.HttpRequest, error) {
	pb := &transformv1.HttpRequest{
		Method:     req.Method,
		Url:        req.URL.String(),
		Host:       req.Host,
		RemoteAddr: req.RemoteAddr,
		Headers:    headersToProto(req.Header),
	}

	if sendBody && req.Body != nil {
		body, err := readBody(req.Body)
		if err != nil {
			return nil, err
		}
		pb.Body = body
	}

	return pb, nil
}

func httpResponseToProto(resp *http.Response, sendBody bool) (*transformv1.HttpResponse, error) {
	pb := &transformv1.HttpResponse{
		StatusCode: int32(resp.StatusCode),
		Headers:    headersToProto(resp.Header),
	}

	if sendBody && resp.Body != nil {
		body, err := readBody(resp.Body)
		if err != nil {
			return nil, err
		}
		pb.Body = body
	}

	return pb, nil
}

// readBody reads the full body. The pipeline handles resetting the body
// between transforms.
func readBody(body io.ReadCloser) ([]byte, error) {
	return io.ReadAll(body)
}

func protoToHTTPResponse(pb *transformv1.HttpResponse, req *http.Request) *http.Response {
	if pb == nil {
		return nil
	}
	resp := &http.Response{
		StatusCode: int(pb.GetStatusCode()),
		Header:     protoToHeaders(pb.GetHeaders()),
		Body:       transform.NewBufferedBodyFromBytes(pb.GetBody()),
		Request:    req,
	}
	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusForbidden
	}
	return resp
}

func applyModifiedRequest(pb *transformv1.HttpRequest, req *http.Request) {
	if pb.GetMethod() != "" {
		req.Method = pb.GetMethod()
	}
	if pb.GetUrl() != "" {
		if u, err := url.Parse(pb.GetUrl()); err == nil {
			req.URL = u
		}
	}
	if pb.GetHost() != "" {
		req.Host = pb.GetHost()
	}
	if len(pb.GetHeaders()) > 0 {
		req.Header = protoToHeaders(pb.GetHeaders())
	}
	if pb.GetBody() != nil {
		req.Body = transform.NewBufferedBodyFromBytes(pb.GetBody())
		req.ContentLength = int64(len(pb.GetBody()))
	}
}

func applyModifiedResponse(pb *transformv1.HttpResponse, resp *http.Response) {
	if pb.GetStatusCode() != 0 {
		resp.StatusCode = int(pb.GetStatusCode())
	}
	if len(pb.GetHeaders()) > 0 {
		resp.Header = protoToHeaders(pb.GetHeaders())
	}
	if pb.GetBody() != nil {
		resp.Body = transform.NewBufferedBodyFromBytes(pb.GetBody())
	}
}

func headersToProto(h http.Header) map[string]*transformv1.HeaderValues {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]*transformv1.HeaderValues, len(h))
	for k, vs := range h {
		out[k] = &transformv1.HeaderValues{Values: vs}
	}
	return out
}

func protoToHeaders(h map[string]*transformv1.HeaderValues) http.Header {
	if len(h) == 0 {
		return make(http.Header)
	}
	out := make(http.Header, len(h))
	for k, vs := range h {
		out[k] = vs.GetValues()
	}
	return out
}
