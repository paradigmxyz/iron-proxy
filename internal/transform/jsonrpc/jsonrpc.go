// Package jsonrpc implements a fail-closed JSON-RPC request policy transform.
package jsonrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"gopkg.in/yaml.v3"
)

const defaultMaxBodyBytes int64 = 1024 * 1024

type ruleConfig struct {
	Host           string   `yaml:"host"`
	Port           string   `yaml:"port"`
	Path           string   `yaml:"path"`
	HTTPMethods    []string `yaml:"http_methods"`
	AllowedMethods []string `yaml:"allowed_methods"`
}

type config struct {
	MaxBodyBytes int64        `yaml:"max_body_bytes"`
	Rules        []ruleConfig `yaml:"rules"`
}

type rule struct {
	host           string
	port           string
	path           string
	httpMethods    map[string]struct{}
	allowedMethods map[string]struct{}
}

type policy struct {
	maxBodyBytes int64
	rules        []rule
}

func init() { transform.Register("json_rpc", factory) }

func factory(node yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var cfg config
	if err := transform.DecodeKnownFields(node, &cfg); err != nil {
		return nil, fmt.Errorf("parsing json_rpc config: %w", err)
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	if cfg.MaxBodyBytes < 1 {
		return nil, fmt.Errorf("json_rpc: max_body_bytes must be positive")
	}
	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("json_rpc: at least one rule is required")
	}
	p := &policy{maxBodyBytes: cfg.MaxBodyBytes}
	for i, source := range cfg.Rules {
		compiled, err := compileRule(source)
		if err != nil {
			return nil, fmt.Errorf("json_rpc: rules[%d]: %w", i, err)
		}
		p.rules = append(p.rules, compiled)
	}
	return p, nil
}

func compileRule(source ruleConfig) (rule, error) {
	host := strings.ToLower(strings.TrimSuffix(source.Host, "."))
	if host == "" || strings.ContainsAny(host, "*?/\\@") {
		return rule{}, fmt.Errorf("host must be an exact hostname")
	}
	portNumber, err := strconv.ParseUint(source.Port, 10, 16)
	if err != nil || portNumber == 0 {
		return rule{}, fmt.Errorf("port must be an integer from 1 through 65535")
	}
	if source.Path == "" || !strings.HasPrefix(source.Path, "/") {
		return rule{}, fmt.Errorf("path must be an absolute exact path")
	}
	if strings.ContainsAny(source.Path, "*?[]\\") {
		return rule{}, fmt.Errorf("path must not contain glob or query syntax")
	}
	if decoded, err := url.PathUnescape(source.Path); err != nil || decoded != source.Path {
		return rule{}, fmt.Errorf("path must use its canonical unescaped spelling")
	}
	if len(source.HTTPMethods) == 0 || len(source.AllowedMethods) == 0 {
		return rule{}, fmt.Errorf("http_methods and allowed_methods must be non-empty")
	}
	result := rule{
		host:           host,
		port:           source.Port,
		path:           source.Path,
		httpMethods:    make(map[string]struct{}, len(source.HTTPMethods)),
		allowedMethods: make(map[string]struct{}, len(source.AllowedMethods)),
	}
	for _, method := range source.HTTPMethods {
		method = strings.ToUpper(method)
		if method == "" || method == "CONNECT" || strings.ContainsAny(method, " \t\r\n") {
			return rule{}, fmt.Errorf("invalid HTTP method %q", method)
		}
		result.httpMethods[method] = struct{}{}
	}
	for _, method := range source.AllowedMethods {
		if method == "" || strings.ContainsAny(method, "*? \t\r\n") {
			return rule{}, fmt.Errorf("JSON-RPC methods must be exact non-empty names")
		}
		result.allowedMethods[method] = struct{}{}
	}
	return result, nil
}

func (p *policy) Name() string { return "json_rpc" }

func (p *policy) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	host, port := hostmatch.HostPort(req)
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var matched *rule
	for i := range p.rules {
		if p.rules[i].host == host && p.rules[i].port == port {
			matched = &p.rules[i]
			break
		}
	}
	if matched == nil {
		return continueResult(), nil
	}

	// CONNECT is only the transport setup. The inner MITM request is parsed
	// and evaluated independently against the exact path and protocol policy.
	if req.Method == http.MethodConnect {
		tctx.Annotate("decision", "tunnel")
		return continueResult(), nil
	}
	if requestPath(req) != matched.path {
		return reject(tctx, "path"), nil
	}
	if _, ok := matched.httpMethods[req.Method]; !ok {
		return reject(tctx, "http_method"), nil
	}
	if isWebSocket(req) {
		return reject(tctx, "websocket"), nil
	}
	if len(req.TransferEncoding) != 0 || req.Header.Get("Transfer-Encoding") != "" {
		return reject(tctx, "transfer_encoding"), nil
	}
	if req.Header.Get("Content-Encoding") != "" {
		return reject(tctx, "content_encoding"), nil
	}
	mediaType, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return reject(tctx, "content_type"), nil
	}
	for key, value := range params {
		if !strings.EqualFold(key, "charset") || !strings.EqualFold(value, "utf-8") {
			return reject(tctx, "content_type"), nil
		}
	}
	if req.ContentLength <= 0 {
		return reject(tctx, "content_length"), nil
	}
	if req.ContentLength > p.maxBodyBytes {
		return reject(tctx, "body_oversize"), nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil || int64(len(body)) != req.ContentLength {
		return reject(tctx, "body_incomplete"), nil
	}
	root, err := decodeUniqueJSON(body)
	if err != nil {
		return reject(tctx, "malformed_json"), nil
	}
	methods, reason := validateEnvelope(root, matched.allowedMethods)
	if reason != "" {
		return reject(tctx, reason), nil
	}
	tctx.Annotate("decision", "allow")
	tctx.Annotate("request_count", len(methods))
	tctx.Annotate("methods", methods)
	return continueResult(), nil
}

func (p *policy) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return continueResult(), nil
}

func continueResult() *transform.TransformResult {
	return &transform.TransformResult{Action: transform.ActionContinue}
}

func reject(tctx *transform.TransformContext, reason string) *transform.TransformResult {
	tctx.Annotate("decision", "reject")
	tctx.Annotate("reason", reason)
	return &transform.TransformResult{Action: transform.ActionReject}
}

func requestPath(req *http.Request) string {
	if req.URL == nil {
		return ""
	}
	if req.URL.RawPath != "" {
		return req.URL.EscapedPath()
	}
	return req.URL.Path
}

func isWebSocket(req *http.Request) bool {
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, value := range req.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func decodeUniqueJSON(body []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	value, err := decodeValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing JSON value")
		}
		return nil, err
	}
	return value, nil
}

func decodeValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("object key is not a string")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, fmt.Errorf("duplicate object key")
			}
			value, err := decodeValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
			return nil, fmt.Errorf("unterminated object")
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := decodeValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if token, err = decoder.Token(); err != nil || token != json.Delim(']') {
			return nil, fmt.Errorf("unterminated array")
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter")
	}
}

func validateEnvelope(root any, allowed map[string]struct{}) ([]string, string) {
	requests, ok := root.([]any)
	if !ok {
		requests = []any{root}
	} else if len(requests) == 0 {
		return nil, "empty_batch"
	}
	methods := make([]string, 0, len(requests))
	for _, item := range requests {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, "invalid_envelope"
		}
		for key := range object {
			if key != "jsonrpc" && key != "id" && key != "method" && key != "params" {
				return nil, "invalid_envelope"
			}
		}
		if object["jsonrpc"] != "2.0" {
			return nil, "invalid_envelope"
		}
		switch object["id"].(type) {
		case string, json.Number:
		default:
			return nil, "notification"
		}
		method, ok := object["method"].(string)
		if !ok || method == "" {
			return nil, "invalid_envelope"
		}
		if params, present := object["params"]; present {
			switch params.(type) {
			case []any, map[string]any:
			default:
				return nil, "invalid_envelope"
			}
		}
		if _, ok := allowed[method]; !ok {
			return nil, "method"
		}
		methods = append(methods, method)
	}
	return methods, ""
}
