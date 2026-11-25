package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stretchr/testify/require"
)

// Verify the complete HTTP proxy path against SDK S3 signatures, including
// preservation of escaped object names during forwarding to the upstream.
func TestAWSAuthEscapedPaths(t *testing.T) {
	observed := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Clone(context.Background())
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	cfgPath := renderConfig(t, t.TempDir(), "awsauth.yaml", nil)
	proxy := startProxy(t, proxyBinary(t), cfgPath, []string{
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
		"AWS_SECRET_ACCESS_KEY=example-secret",
	})
	upstreamHost := upstream.Listener.Addr().String()
	cases := []struct{ name, path string }{
		{"plain", "/bucket/hero.png"},
		{"at2x", "/bucket/hero%402x.png"},
		{"space", "/bucket/hero%20large.png"},
		{"unicode", "/bucket/%E6%97%A5%E6%9C%AC%E8%AA%9E.png"},
		{"percent", "/bucket/100%25.png"},
		{"literal escape", "/bucket/hero%25402x.png"},
		{"plus", "/bucket/hero%2Blarge.png"},
		{"hash and question", "/bucket/hero%23%3F.png"},
		{"escaped slash", "/bucket/a%2Fb.png"},
		{"repeated slash", "/bucket/a//b.png"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, service := range []string{"s3", "bedrock"} {
				for _, method := range []string{http.MethodPut, http.MethodHead, http.MethodGet} {
					t.Run(service+method, func(t *testing.T) {
						uri := tc.path + "?prefix=a%20b%2Bc%25&x=1"
						req, err := http.NewRequest(method, "http://"+proxy.HTTPAddr+uri, nil)
						require.NoError(t, err)
						req.Host = upstreamHost
						if method == http.MethodPut {
							req.Header.Set("If-None-Match", "*")
						}
						sum := sha256.Sum256(nil)
						hash := hex.EncodeToString(sum[:])
						require.NoError(t, v4.NewSigner().SignHTTP(context.Background(),
							aws.Credentials{AccessKeyID: "PLACEHOLDER", SecretAccessKey: "placeholder"},
							req, hash, service, "us-east-1", time.Now().UTC(), func(o *v4.SignerOptions) {
								o.DisableURIPathEscaping = service == "s3"
							}))
						resp, err := http.DefaultClient.Do(req)
						require.NoError(t, err)
						_, err = io.Copy(io.Discard, resp.Body)
						require.NoError(t, err)
						require.NoError(t, resp.Body.Close())
						require.Equal(t, http.StatusOK, resp.StatusCode)
						var got *http.Request
						select {
						case got = <-observed:
						case <-time.After(5 * time.Second):
							t.Fatal("upstream did not receive request")
						}
						require.Equal(t, uri, got.RequestURI)
						if method == http.MethodPut {
							require.Equal(t, "*", got.Header.Get("If-None-Match"))
						}
						// Recompute the signature from what actually arrived, using the
						// SDK's service-specific options and only the declared signed headers.
						auth := got.Header.Get("Authorization")
						_, signed, found := strings.Cut(auth, "SignedHeaders=")
						require.True(t, found)
						signed, _, found = strings.Cut(signed, ",")
						require.True(t, found)
						expected := got.Clone(context.Background())
						expected.URL, err = url.Parse("http://" + upstreamHost + uri)
						require.NoError(t, err)
						expected.Header = make(http.Header)
						for _, name := range strings.Split(signed, ";") {
							if name != "host" {
								expected.Header[http.CanonicalHeaderKey(name)] = got.Header.Values(name)
							}
						}
						when, err := time.Parse("20060102T150405Z", got.Header.Get("X-Amz-Date"))
						require.NoError(t, err)
						require.NoError(t, v4.NewSigner().SignHTTP(context.Background(),
							aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "example-secret"},
							expected, hash, service, "us-east-1", when, func(o *v4.SignerOptions) {
								o.DisableURIPathEscaping = service == "s3"
							}))
						require.Equal(t, expected.Header.Get("Authorization"), auth)
					})
				}
			}
		})
	}
}

// TestAWSAuth boots the proxy with the aws_auth transform configured and
// verifies that an SDK-signed request arrives at the upstream with a fresh
// signature minted from the proxy's real credentials, not the placeholder
// the client used.
func TestAWSAuth(t *testing.T) {
	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	var (
		mu      sync.Mutex
		gotAuth string
		gotDate string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		gotDate = r.Header.Get("X-Amz-Date")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfgPath := renderConfig(t, tmpDir, "awsauth.yaml", nil)
	env := []string{
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	proxy := startProxy(t, binary, cfgPath, env)
	upstreamHost := upstream.Listener.Addr().String()

	body := []byte(`{"prompt":"hi"}`)
	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/model/foo/invoke", proxy.HTTPAddr), strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Host = upstreamHost
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	// Sign with placeholder credentials, like an AWS SDK would when configured
	// to talk to a sigv4 proxy. The proxy is expected to read the scope, drop
	// this signature, and re-sign with the real env-provided credentials.
	placeholder := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	sum := sha256.Sum256(body)
	require.NoError(t, v4.NewSigner().SignHTTP(
		context.Background(), placeholder, req, hex.EncodeToString(sum[:]),
		"bedrock", "us-east-1", time.Now().UTC(),
	))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	require.True(t, strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 "), "Authorization = %q", gotAuth)
	require.Contains(t, gotAuth, "Credential=AKIAEXAMPLE/")
	require.NotContains(t, gotAuth, "AKIAIOSFODNN7EXAMPLE", "placeholder credential must not appear in outbound Authorization header")
	require.Contains(t, gotAuth, "/us-east-1/bedrock/aws4_request")
	require.Contains(t, gotAuth, "SignedHeaders=")
	require.Contains(t, gotAuth, "Signature=")
	require.Regexp(t, `^\d{8}T\d{6}Z$`, gotDate)
}
