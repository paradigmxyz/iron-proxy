package transform

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTunnelInfo_CredentialNotSerialized(t *testing.T) {
	blob, err := json.Marshal(&TunnelInfo{Target: "example.com:443", Credential: "Basic c2VjcmV0"})
	require.NoError(t, err)
	require.Contains(t, string(blob), "example.com:443")
	require.NotContains(t, string(blob), "c2VjcmV0")
	require.NotContains(t, string(blob), "Credential")
}
