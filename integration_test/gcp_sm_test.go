package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGCPSecretManager boots the proxy with real GCP Secret Manager secrets
// and verifies that proxy tokens in request headers are swapped for real values.
func TestGCPSecretManager(t *testing.T) {
	keyfile := requireEnv(t, "GCP_BIGQUERY_SERVICE_ACCOUNT_KEY_FILE")
	project := requireEnv(t, "GCP_SM_PROJECT")

	cases := []struct {
		name, header, sent, want string
	}{
		{"raw_secret", "X-Raw-Secret", "proxy-raw-secret", "example-value"},
		{"json_secret", "X-Json-Secret", "proxy-json-secret", "example-value"},
	}

	headers := make([]string, len(cases))
	for i, tc := range cases {
		headers[i] = tc.header
	}
	upstreamHost := echoHeadersUpstream(t, headers...)

	cfgPath := renderConfig(t, t.TempDir(), "gcp_sm.yaml", struct{ Project string }{project})
	proxy := startProxy(t, proxyBinary(t), cfgPath, []string{"GOOGLE_APPLICATION_CREDENTIALS=" + keyfile})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, hdr := proxyGet(t, proxy.HTTPAddr, upstreamHost, map[string]string{tc.header: tc.sent})
			require.Equal(t, http.StatusOK, status)
			require.Equal(t, tc.want, hdr.Get(echoedHeaderName(tc.header)))
		})
	}
}
