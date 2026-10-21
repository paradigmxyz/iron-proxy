package integration_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSecretSelectionReload(t *testing.T) {
	const (
		secretA       = "upstream-secret-a"
		secretB       = "upstream-secret-b-before"
		rotatedB      = "upstream-secret-b-after"
		secretC       = "upstream-secret-c"
		managementKey = "selection-test-management-key"
	)
	t.Setenv("IRON_SELECTION_SECRET_A", secretA)
	t.Setenv("IRON_SELECTION_SECRET_C", secretC)
	t.Setenv("IRON_SELECTION_MANAGEMENT_KEY", managementKey)

	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		account := map[string]string{
			"Bearer " + secretA:  "a",
			"Bearer " + secretB:  "b-before",
			"Bearer " + rotatedB: "b-after",
			"Bearer " + secretC:  "c",
		}[r.Header.Get("Authorization")]
		if account == "" {
			http.Error(w, "unexpected credential", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/held" {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		// Request-side assertions detect truncation; cleanup can cancel this handler.
		_, _ = io.WriteString(w, account)
	}))
	t.Cleanup(func() {
		unblock()
		upstream.Close()
	})

	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "account-b")
	require.NoError(t, os.WriteFile(secretPath, []byte(secretB), 0o600))
	data := struct {
		SecretPathB string
		IncludeC    bool
	}{SecretPathB: secretPath}
	configPath := renderConfig(t, tmpDir, "selection.yaml", data)
	proxy := startProxy(t, proxyBinary(t), configPath, nil)
	managementAddr := proxy.AddrFor(t, "management server starting")
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 10 * time.Second}

	request := func(path string, values []string) *http.Request {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+proxy.HTTPAddr+path, nil)
		require.NoError(t, err)
		req.Host = strings.TrimPrefix(upstream.URL, "http://")
		req.Header["Authorization"] = values
		return req
	}
	check := func(req *http.Request, status int, body string) {
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { require.NoError(t, resp.Body.Close()) }()
		got, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, status, resp.StatusCode)
		require.Equal(t, body, string(got))
	}

	check(request("/", []string{"Bearer account-a"}), http.StatusOK, "a")
	check(request("/", []string{"Bearer account-b"}), http.StatusOK, "b-before")
	for _, values := range [][]string{
		nil,
		{"Bearer unknown"},
		{"Bearer " + secretA},
		{"Bearer account-a", "Bearer account-b"},
		{"Bearer account-a", "Bearer unknown"},
		{"Bearer prefix-account-a"},
		{"Bearer account-c"},
	} {
		before := upstreamCalls.Load()
		resp, err := client.Do(request("/", values))
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		require.Equal(t, before, upstreamCalls.Load())
	}

	type response struct {
		status int
		body   string
		err    error
	}
	held := make(chan response, 1)
	heldRequest := request("/held", []string{"Bearer account-b"})
	go func() {
		resp, err := client.Do(heldRequest)
		if err != nil {
			held <- response{err: err}
			return
		}
		body, err := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if err == nil {
			err = closeErr
		}
		held <- response{status: resp.StatusCode, body: string(body), err: err}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		require.FailNow(t, "held request did not reach upstream", "%v", ctx.Err())
	}

	staged := secretPath + ".next"
	require.NoError(t, os.WriteFile(staged, []byte(rotatedB), 0o600))
	require.NoError(t, os.Rename(staged, secretPath))
	data.IncludeC = true
	require.Equal(t, configPath, renderConfig(t, tmpDir, "selection.yaml", data))
	reload, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+managementAddr+"/v1/reload", nil)
	require.NoError(t, err)
	reload.Header.Set("Authorization", "Bearer "+managementKey)
	check(reload, http.StatusOK, "{\"status\":\"ok\"}\n")

	check(request("/", []string{"Bearer account-a"}), http.StatusOK, "a")
	check(request("/", []string{"Bearer account-b"}), http.StatusOK, "b-after")
	check(request("/", []string{"Bearer account-c"}), http.StatusOK, "c")
	unblock()
	select {
	case got := <-held:
		require.NoError(t, got.err)
		require.Equal(t, http.StatusOK, got.status)
		require.Equal(t, "b-before", got.body)
	case <-ctx.Done():
		require.FailNow(t, "held request did not complete after reload", "%v", ctx.Err())
	}
}
