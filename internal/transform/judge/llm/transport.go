package llm

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ironsh/iron-proxy/internal/transform"
)

const defaultMaxTokens = 256

// buildTransport mirrors the proxy's upstream-transport timeouts so a stuck
// LLM endpoint can't hold a goroutine past the per-call context timeout.
func buildTransport() *http.Transport {
	return &http.Transport{
		DialContext:           transform.DialOutbound,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// resolveAPIKey reads the named env var. Returns a descriptive error when
// the var is unset or empty so misconfigurations fail fast at startup.
func resolveAPIKey(provider, envVar string) (string, error) {
	if envVar == "" {
		return "", fmt.Errorf("%s provider: api_key_env is required", provider)
	}
	v := os.Getenv(envVar)
	if v == "" {
		return "", fmt.Errorf("%s provider: env var %q is empty", provider, envVar)
	}
	return v, nil
}

// truncateForError bounds an HTTP error-body snippet to 512 bytes.
func truncateForError(b []byte) string {
	const max = 512
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}
