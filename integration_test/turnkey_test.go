package integration_test

import (
	"crypto/subtle"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTurnkeyManagedSecret(t *testing.T) {
	organizationID := os.Getenv("TURNKEY_INTEGRATION_ORGANIZATION_ID")
	secretID := os.Getenv("TURNKEY_INTEGRATION_SECRET_ID")
	expectedFile := os.Getenv("TURNKEY_INTEGRATION_EXPECTED_FILE")
	if organizationID == "" || secretID == "" || expectedFile == "" || os.Getenv("TURNKEY_API_PRIVATE_KEY") == "" {
		t.Skip("requires disposable Turnkey integration credentials and an expected-value file")
	}
	expected, err := os.ReadFile(expectedFile)
	require.NoError(t, err)
	require.NotEmpty(t, expected)
	wantAuthorization := append([]byte("Bearer "), expected...)
	t.Cleanup(func() { clear(expected); clear(wantAuthorization) })

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), wantAuthorization) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Credential-Validated", "true")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfgPath := renderConfig(t, t.TempDir(), "turnkey.yaml", struct {
		OrganizationID string
		SecretID       string
	}{OrganizationID: organizationID, SecretID: secretID})
	proxy := startProxy(t, proxyBinary(t), cfgPath, nil)

	cases := []struct {
		name   string
		token  string
		status int
	}{
		{name: "injected credential verified upstream", token: "Bearer proxy-turnkey-secret", status: http.StatusOK},
		{name: "missing placeholder rejected", status: http.StatusForbidden},
		{name: "alternative credential rejected", token: "Bearer wrong-public-placeholder", status: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, headers := proxyGet(t, proxy.HTTPAddr, upstream.Listener.Addr().String(), map[string]string{"Authorization": tc.token})
			require.Equal(t, tc.status, status)
			if status == http.StatusOK {
				require.Equal(t, "true", headers.Get("X-Credential-Validated"))
			}
		})
	}
}
