package secrets

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// newTestGCPSMBuilder points a gcp_sm builder at handler. It authenticates
// with a static token through the production redirect-refusing client.
func newTestGCPSMBuilder(t *testing.T, handler http.HandlerFunc) *gcpSMBuilder {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := newGCPSMHTTPClient(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}))
	return &gcpSMBuilder{
		clientFor: func(context.Context) (*http.Client, error) { return client, nil },
		endpoint:  func(string) string { return srv.URL },
		logger:    slog.Default(),
	}
}

// writeGCPSMPayload writes an :access response. encoding/json base64-encodes
// the []byte payload the same way the real API does.
func writeGCPSMPayload(w http.ResponseWriter, payload string) {
	w.Header().Set("Content-Type", "application/json")
	// A write failure means the client went away; the Get under test reports it.
	_ = json.NewEncoder(w).Encode(map[string]any{"payload": map[string]any{"data": []byte(payload)}})
}

func TestGCPSMBuilder_Access(t *testing.T) {
	require.Equal(t, "https://secretmanager.googleapis.com", gcpSMEndpoint(""))
	require.Equal(t, "https://secretmanager.us-east1.rep.googleapis.com", gcpSMEndpoint("us-east1"))

	cases := []struct {
		name     string
		input    map[string]any
		wantPath string
		wantName string
	}{
		{
			name:     "global secret defaults to latest",
			input:    map[string]any{"type": "gcp_sm", "project": "my-proj", "secret": "api-key"},
			wantPath: "/v1/projects/my-proj/secrets/api-key/versions/latest:access",
			wantName: "gcp_sm:projects/my-proj/secrets/api-key/versions/latest",
		},
		{
			name:     "regional secret with unquoted numeric project and version",
			input:    map[string]any{"type": "gcp_sm", "project": 123456789012, "secret": "api-key", "version": 3, "location": "us-east1"},
			wantPath: "/v1/projects/123456789012/locations/us-east1/secrets/api-key/versions/3:access",
			wantName: "gcp_sm:projects/123456789012/locations/us-east1/secrets/api-key/versions/3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			type request struct{ path, auth string }
			requests := make(chan request, 1)
			builder := newTestGCPSMBuilder(t, func(w http.ResponseWriter, r *http.Request) {
				requests <- request{path: r.URL.Path, auth: r.Header.Get("Authorization")}
				writeGCPSMPayload(w, "real-value")
			})

			source, err := builder.Build(yamlNode(t, tc.input))
			require.NoError(t, err)
			require.Equal(t, tc.wantName, source.Name())

			value, err := source.Get(context.Background())
			require.NoError(t, err)
			require.Equal(t, "real-value", value)

			got := <-requests
			require.Equal(t, tc.wantPath, got.path)
			require.Equal(t, "Bearer test-token", got.auth)
		})
	}
}

func TestGCPSMBuilder_ConfigErrors(t *testing.T) {
	cases := []struct {
		name   string
		input  map[string]any
		errMsg string
	}{
		{
			name:   "missing project",
			input:  map[string]any{"type": "gcp_sm", "secret": "api-key"},
			errMsg: `requires "project" field`,
		},
		{
			name:   "missing secret",
			input:  map[string]any{"type": "gcp_sm", "project": "my-proj"},
			errMsg: `requires "secret" field`,
		},
		{
			name:   "location cannot change host",
			input:  map[string]any{"type": "gcp_sm", "project": "my-proj", "secret": "api-key", "location": "evil.com"},
			errMsg: "invalid location",
		},
		{
			name:   "secret cannot traverse path",
			input:  map[string]any{"type": "gcp_sm", "project": "my-proj", "secret": "../x"},
			errMsg: "invalid secret",
		},
		{
			name:   "version cannot add fragment",
			input:  map[string]any{"type": "gcp_sm", "project": "my-proj", "secret": "api-key", "version": "1#x"},
			errMsg: "invalid version",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newGCPSMBuilder(slog.Default()).Build(yamlNode(t, tc.input))
			require.ErrorContains(t, err, tc.errMsg)
		})
	}
}

func TestGCPSMBuilder_FetchErrors(t *testing.T) {
	cases := []struct {
		name      string
		statuses  []int
		payload   string
		wantValue string
		wantErr   string
		wantCalls int64
	}{
		{
			name:      "permission denied is not retried",
			statuses:  []int{http.StatusForbidden},
			wantErr:   "HTTP 403: Permission denied",
			wantCalls: 1,
		},
		{
			name:      "unavailable is retried",
			statuses:  []int{http.StatusServiceUnavailable, http.StatusOK},
			payload:   "real-value",
			wantValue: "real-value",
			wantCalls: 2,
		},
		{
			name:      "redirect is refused",
			statuses:  []int{http.StatusFound},
			wantErr:   "HTTP 302",
			wantCalls: 1,
		},
		{
			name:      "empty payload",
			statuses:  []int{http.StatusOK},
			wantErr:   "empty value",
			wantCalls: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			builder := newTestGCPSMBuilder(t, func(w http.ResponseWriter, r *http.Request) {
				switch status := tc.statuses[calls.Add(1)-1]; status {
				case http.StatusOK:
					writeGCPSMPayload(w, tc.payload)
				case http.StatusFound:
					http.Redirect(w, r, "/elsewhere", status)
				default:
					w.WriteHeader(status)
					// A write failure means the client went away; the Get under test reports it.
					_, _ = io.WriteString(w, `{"error":{"code":403,"message":"Permission denied"}}`)
				}
			})

			source, err := builder.Build(yamlNode(t, map[string]any{"type": "gcp_sm", "project": "my-proj", "secret": "api-key"}))
			require.NoError(t, err)

			value, err := source.Get(context.Background())
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.wantValue, value)
			require.Equal(t, tc.wantCalls, calls.Load())
		})
	}
}
