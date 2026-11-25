package secrets

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAWSSources_RejectInvalidRegion(t *testing.T) {
	cases := []struct {
		name   string
		raw    map[string]string
		prefix string
	}{
		{
			name:   "aws_sm",
			raw:    map[string]string{"type": "aws_sm", "secret_id": "my-secret"},
			prefix: "aws_sm source",
		},
		{
			name:   "aws_ssm",
			raw:    map[string]string{"type": "aws_ssm", "name": "/my/param"},
			prefix: "aws_ssm source",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, region := range []string{"us-east-1.evil.example", "US-EAST-1", "../latest", "us-east"} {
				t.Run(region, func(t *testing.T) {
					tc.raw["region"] = region
					var builder secretSourceBuilder
					switch tc.name {
					case "aws_sm":
						builder = newAWSSMBuilder(slog.Default())
					case "aws_ssm":
						builder = newAWSSSMBuilder(slog.Default())
					}
					_, err := builder.Build(yamlNode(t, tc.raw))
					require.ErrorContains(t, err, tc.prefix)
					require.ErrorContains(t, err, "invalid AWS region")
				})
			}
		})
	}
}
