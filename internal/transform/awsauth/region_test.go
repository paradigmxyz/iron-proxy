package awsauth

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWorkloadIdentityProvider_RejectsInvalidRegion(t *testing.T) {
	for _, region := range []string{"us-east-1.evil.example", "US-EAST-1", "../latest", "us-east"} {
		t.Run(region, func(t *testing.T) {
			node := yamlFromString(t, "type: workload_identity\nregion: \""+region+"\"\n")
			_, err := BuildCredentialsProvider(node, slog.Default())
			require.ErrorContains(t, err, "credentials_provider region")
			require.ErrorContains(t, err, "invalid AWS region")
		})
	}
}
