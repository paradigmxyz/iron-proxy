// Package hmacsign implements a generic HMAC request-signing transform.
//
// It computes an HMAC signature over a configurable message template derived
// from the request (timestamp, method, path, query, host, body) and injects
// the resulting signature plus any auxiliary credentials into a configurable
// set of request headers. The same transform configures cleanly for
// FalconX-, Coinbase Prime-, and similar venue auth schemes.
//
// Because a truncated request body would produce an invalid signature, the
// transform rejects any request whose body cannot be verified intact: a body
// that came up short of its Content-Length (truncated by the proxy's global
// max_request_body_bytes), or — by default — a chunked body whose length
// the proxy cannot verify. Set allow_chunked_body: true to opt out of the
// chunked-body check.
//
// Like all header-injecting transforms this requires MITM mode; sni-only
// mode has no method, path, or body to sign.
package hmacsign

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/headers"
	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

func init() {
	transform.Register("hmac_sign", factory)
}

// credentialSecretField is the conventional name of the credential whose
// resolved value is used as the HMAC key. It is required in every config.
const credentialSecretField = "secret"

type config struct {
	Timestamp        timestampConfig        `yaml:"timestamp"`
	Signature        signatureConfig        `yaml:"signature"`
	Credentials      map[string]yaml.Node   `yaml:"credentials"`
	Headers          []headerConfig         `yaml:"headers"`
	AllowChunkedBody bool                   `yaml:"allow_chunked_body,omitempty"`
	Rules            []hostmatch.RuleConfig `yaml:"rules"`
}

type timestampConfig struct {
	Format string `yaml:"format"`
}

type signatureConfig struct {
	Algorithm      string `yaml:"algorithm"`
	KeyEncoding    string `yaml:"key_encoding"`
	OutputEncoding string `yaml:"output_encoding"`
	Message        string `yaml:"message"`
}

type headerConfig struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// sourceBuilder is the signature of secrets.BuildSource. Pulled out so tests
// can inject a stub instead of constructing real source backends.
type sourceBuilder func(yaml.Node, *slog.Logger) (secrets.Source, error)

// HMACSign is the transform.
type HMACSign struct {
	logger           *slog.Logger
	rules            []hostmatch.Rule
	credentials      map[string]secrets.Source
	msgTmpl          *template.Template
	headerTmpls      []compiledHeader
	timestampFn      func(time.Time) string
	now              func() time.Time
	newHash          func() hash.Hash
	decodeKey        func([]byte) ([]byte, error)
	encodeSignature  func([]byte) string
	allowChunkedBody bool
}

type compiledHeader struct {
	name string // exact casing the user wrote in YAML
	tmpl *template.Template
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing hmac_sign config: %w", err)
	}
	return newFromConfig(c, logger, secrets.BuildSource)
}

func newFromConfig(c config, logger *slog.Logger, build sourceBuilder) (*HMACSign, error) {
	tsFn, err := compileTimestampFormat(c.Timestamp.Format)
	if err != nil {
		return nil, err
	}
	newHash, err := compileAlgorithm(c.Signature.Algorithm)
	if err != nil {
		return nil, err
	}
	decodeKey, err := compileKeyEncoding(c.Signature.KeyEncoding)
	if err != nil {
		return nil, err
	}
	encodeSig, err := compileOutputEncoding(c.Signature.OutputEncoding)
	if err != nil {
		return nil, err
	}
	if c.Signature.Message == "" {
		return nil, fmt.Errorf("hmac_sign: signature.message is required")
	}
	msgTmpl, err := template.New("hmac_sign.message").Option("missingkey=error").Parse(c.Signature.Message)
	if err != nil {
		return nil, fmt.Errorf("hmac_sign: parsing signature.message: %w", err)
	}

	if len(c.Headers) == 0 {
		return nil, fmt.Errorf("hmac_sign: at least one entry in \"headers\" is required")
	}
	headerTmpls := make([]compiledHeader, 0, len(c.Headers))
	for i, h := range c.Headers {
		if h.Name == "" {
			return nil, fmt.Errorf("hmac_sign: headers[%d].name is required", i)
		}
		if h.Value == "" {
			return nil, fmt.Errorf("hmac_sign: headers[%d].value is required", i)
		}
		t, err := template.New(fmt.Sprintf("hmac_sign.header[%d]", i)).Option("missingkey=error").Parse(h.Value)
		if err != nil {
			return nil, fmt.Errorf("hmac_sign: parsing headers[%d].value: %w", i, err)
		}
		headerTmpls = append(headerTmpls, compiledHeader{name: h.Name, tmpl: t})
	}

	if len(c.Credentials) == 0 {
		return nil, fmt.Errorf("hmac_sign: \"credentials\" must include at least %q", credentialSecretField)
	}
	if _, ok := c.Credentials[credentialSecretField]; !ok {
		return nil, fmt.Errorf("hmac_sign: \"credentials\" must include %q (the HMAC key)", credentialSecretField)
	}
	creds := make(map[string]secrets.Source, len(c.Credentials))
	for name, node := range c.Credentials {
		src, err := build(node, logger)
		if err != nil {
			return nil, fmt.Errorf("hmac_sign: building credentials[%q] source: %w", name, err)
		}
		creds[name] = src
	}

	rules, err := hostmatch.CompileRulesAllowRequireTLS(c.Rules, "hmac_sign")
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("hmac_sign: at least one entry in \"rules\" is required")
	}

	return &HMACSign{
		logger:           logger,
		rules:            rules,
		credentials:      creds,
		msgTmpl:          msgTmpl,
		headerTmpls:      headerTmpls,
		timestampFn:      tsFn,
		now:              time.Now,
		newHash:          newHash,
		decodeKey:        decodeKey,
		encodeSignature:  encodeSig,
		allowChunkedBody: c.AllowChunkedBody,
	}, nil
}

func (h *HMACSign) Name() string { return "hmac_sign" }

func (h *HMACSign) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if !hostmatch.MatchAnyRule(h.rules, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	body, ok, reject := h.readBodyForSigning(tctx, req)
	if !ok {
		return reject, nil
	}

	credValues := make(map[string]string, len(h.credentials))
	for name, src := range h.credentials {
		v, err := src.Get(ctx)
		if err != nil {
			tctx.Annotate("rejected", "credential_unavailable")
			tctx.Annotate("credential", name)
			tctx.Annotate("error", err.Error())
			return &transform.TransformResult{
				Action:   transform.ActionReject,
				Response: errorResponse(req, http.StatusBadGateway, "credential_unavailable"),
			}, nil
		}
		credValues[name] = v
	}

	timestamp := h.timestampFn(h.now())
	msgData := messageData{
		Timestamp:     timestamp,
		Method:        req.Method,
		Path:          req.URL.Path,
		PathWithQuery: pathWithQuery(req.URL.Path, req.URL.RawQuery),
		Query:         req.URL.RawQuery,
		Host:          hostmatch.StripPort(req.Host),
		Body:          string(body),
	}
	var msgBuf strings.Builder
	if err := h.msgTmpl.Execute(&msgBuf, msgData); err != nil {
		tctx.Annotate("rejected", "message_template_failed")
		tctx.Annotate("error", err.Error())
		return &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusInternalServerError, "message_template_failed"),
		}, nil
	}

	key, err := h.decodeKey([]byte(credValues[credentialSecretField]))
	if err != nil {
		tctx.Annotate("rejected", "key_decode_failed")
		tctx.Annotate("error", err.Error())
		return &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusInternalServerError, "key_decode_failed"),
		}, nil
	}
	mac := hmac.New(h.newHash, key)
	mac.Write([]byte(msgBuf.String()))
	signature := h.encodeSignature(mac.Sum(nil))

	hdrData := headerData{
		Timestamp:   timestamp,
		Signature:   signature,
		Credentials: credValues,
	}
	injected := make([]string, 0, len(h.headerTmpls))
	for _, hdr := range h.headerTmpls {
		var buf strings.Builder
		if err := hdr.tmpl.Execute(&buf, hdrData); err != nil {
			tctx.Annotate("rejected", "header_template_failed")
			tctx.Annotate("header", hdr.name)
			tctx.Annotate("error", err.Error())
			return &transform.TransformResult{
				Action:   transform.ActionReject,
				Response: errorResponse(req, http.StatusInternalServerError, "header_template_failed"),
			}, nil
		}
		headers.Set(req.Header, hdr.name, buf.String())
		injected = append(injected, "header:"+hdr.name)
	}

	req.Body = transform.NewBufferedBodyFromBytes(body)
	tctx.Annotate("injected", injected)
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (h *HMACSign) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// readBodyForSigning buffers the request body and verifies it was not silently
// truncated by the proxy's global max_request_body_bytes cap. A truncated body
// would produce a signature the upstream venue rejects, which is harder to
// debug than a clean proxy-side rejection.
//
// Returns (body, true, nil) when safe to sign. Otherwise returns
// (nil, false, rejectResult) — the caller should propagate rejectResult.
func (h *HMACSign) readBodyForSigning(tctx *transform.TransformContext, req *http.Request) ([]byte, bool, *transform.TransformResult) {
	if req.Body == nil || req.Body == http.NoBody {
		if req.ContentLength > 0 {
			tctx.Annotate("rejected", "body_missing")
			tctx.Annotate("content_length", req.ContentLength)
			return nil, false, &transform.TransformResult{
				Action:   transform.ActionReject,
				Response: errorResponse(req, http.StatusBadRequest, "body_missing"),
			}
		}
		return nil, true, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		tctx.Annotate("rejected", "body_read_failed")
		tctx.Annotate("error", err.Error())
		return nil, false, &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusBadRequest, "body_read_failed"),
		}
	}

	switch {
	case req.ContentLength >= 0 && int64(len(body)) < req.ContentLength:
		// BufferedBody silently truncates at maxBytes; len(body) shorter than
		// the client-declared Content-Length is unambiguous evidence.
		tctx.Annotate("rejected", "body_truncated")
		tctx.Annotate("content_length", req.ContentLength)
		tctx.Annotate("buffered_length", len(body))
		return nil, false, &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusRequestEntityTooLarge, "body_truncated"),
		}

	case req.ContentLength < 0 && !h.allowChunkedBody:
		// Chunked / unknown length: cannot prove the body wasn't truncated.
		tctx.Annotate("rejected", "chunked_body_not_allowed")
		return nil, false, &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusBadRequest, "chunked_body_not_allowed"),
		}

	case req.ContentLength < 0 && h.allowChunkedBody:
		h.logger.Warn("hmac_sign signing chunked request body without length verification",
			"host", hostmatch.StripPort(req.Host),
			"path", req.URL.Path,
			"buffered_length", len(body),
		)
	}

	return body, true, nil
}

// messageData is the template context for signature.message.
type messageData struct {
	Timestamp     string
	Method        string
	Path          string
	PathWithQuery string
	Query         string
	Host          string
	Body          string
}

// headerData is the template context for each headers[].value.
type headerData struct {
	Timestamp   string
	Signature   string
	Credentials map[string]string
}

func pathWithQuery(path, rawQuery string) string {
	if rawQuery == "" {
		return path
	}
	return path + "?" + rawQuery
}

func compileTimestampFormat(format string) (func(time.Time) string, error) {
	switch format {
	case "", "unix_seconds":
		return func(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }, nil
	case "unix_millis":
		return func(t time.Time) string { return strconv.FormatInt(t.UnixMilli(), 10) }, nil
	case "unix_nanos":
		return func(t time.Time) string { return strconv.FormatInt(t.UnixNano(), 10) }, nil
	case "rfc3339":
		return func(t time.Time) string { return t.UTC().Format(time.RFC3339) }, nil
	}
	return nil, fmt.Errorf("hmac_sign: unknown timestamp.format %q (want unix_seconds|unix_millis|unix_nanos|rfc3339)", format)
}

func compileAlgorithm(algo string) (func() hash.Hash, error) {
	switch algo {
	case "", "sha256":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	case "sha1":
		return sha1.New, nil
	}
	return nil, fmt.Errorf("hmac_sign: unknown signature.algorithm %q (want sha256|sha512|sha1)", algo)
}

func compileKeyEncoding(enc string) (func([]byte) ([]byte, error), error) {
	switch enc {
	case "", "raw":
		return func(b []byte) ([]byte, error) { return b, nil }, nil
	case "base64":
		return func(b []byte) ([]byte, error) {
			out, err := base64.StdEncoding.DecodeString(string(b))
			if err != nil {
				return nil, fmt.Errorf("decoding base64 key: %w", err)
			}
			return out, nil
		}, nil
	case "hex":
		return func(b []byte) ([]byte, error) {
			out, err := hex.DecodeString(string(b))
			if err != nil {
				return nil, fmt.Errorf("decoding hex key: %w", err)
			}
			return out, nil
		}, nil
	}
	return nil, fmt.Errorf("hmac_sign: unknown signature.key_encoding %q (want raw|base64|hex)", enc)
}

func compileOutputEncoding(enc string) (func([]byte) string, error) {
	switch enc {
	case "", "base64":
		return base64.StdEncoding.EncodeToString, nil
	case "hex":
		return hex.EncodeToString, nil
	}
	return nil, fmt.Errorf("hmac_sign: unknown signature.output_encoding %q (want base64|hex)", enc)
}

func errorResponse(req *http.Request, status int, reason string) *http.Response {
	body := []byte(`{"error":"hmac_sign","reason":"` + reason + `"}`)
	return &http.Response{
		StatusCode:    status,
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          transform.NewBufferedBodyFromBytes(body),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
