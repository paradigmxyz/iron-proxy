package proxy

import (
	"net/http"

	"github.com/ironsh/iron-proxy/internal/tenancy"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// tenancyErrorHeader tells a tenancy client why it was refused.
const tenancyErrorHeader = "X-Iron-Proxy-Error"

var (
	// tenancyMissing refuses a request in tenancy mode that did not arrive
	// through a tenant's tunnel (the plain HTTP/HTTPS listeners).
	tenancyMissing = &tenancy.Rejection{Status: http.StatusProxyAuthRequired, Code: "tenant_token_required", Challenge: true}
	// tenancySOCKS5 records a refused SOCKS5 handshake: SOCKS5 has no place
	// for a tenant token.
	tenancySOCKS5 = &tenancy.Rejection{Status: http.StatusProxyAuthRequired, Code: "socks5_refused"}
)

// writeTenancyRejection answers a refused tenancy request. A challenge asks
// for a bearer tenant token.
func writeTenancyRejection(w http.ResponseWriter, rej *tenancy.Rejection) {
	if rej.Challenge {
		w.Header().Set("Proxy-Authenticate", `Bearer realm="iron-proxy"`)
	}
	w.Header().Set(tenancyErrorHeader, rej.Code)
	http.Error(w, rej.Code, rej.Status)
}

// markTenancyReject records a tenancy refusal on a request's audit result.
func markTenancyReject(result *transform.PipelineResult, rej *tenancy.Rejection) {
	result.Action = transform.ActionReject
	result.StatusCode = rej.Status
	result.RequestTransforms = append(result.RequestTransforms, transform.TransformTrace{
		Name:   "tenancy",
		Action: transform.ActionReject,
		Annotations: map[string]any{
			"reason": rej.Code,
		},
	})
}

// auditTenancyRejection emits the audit record for a request refused before
// it was bound to a tenant. It runs through the base pipeline, which carries
// the audit function.
func (p *Proxy) auditTenancyRejection(remoteAddr, host, method, path string, rej *tenancy.Rejection) {
	result := &transform.PipelineResult{
		Host:       host,
		Method:     method,
		Path:       path,
		RemoteAddr: remoteAddr,
		Mode:       transform.ModeMITM,
	}
	_, finish := p.beginPipelineRun(result, nil)
	markTenancyReject(result, rej)
	finish()
}

// withoutProxyAuthorization returns h without Proxy-Authorization, so no
// transform ever sees the tenant token it carries.
func withoutProxyAuthorization(h http.Header) http.Header {
	h = h.Clone()
	h.Del("Proxy-Authorization")
	return h
}
