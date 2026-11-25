package transform

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateAWSRegion(t *testing.T) {
	valid := []string{
		"us-east-1",
		"us-gov-west-1",
		"cn-north-1",
		"eu-central-2",
		"ap-southeast-4",
		"il-central-1",
		"mx-central-1",
		"us-iso-east-1",
		"us-isob-east-1",
		"eu-isoe-west-1",
		"us-isof-south-1",
		"eusc-de-east-1",
		"ca-west-1",
		"cn-northwest-1",
	}
	for _, region := range valid {
		t.Run(region, func(t *testing.T) {
			require.NoError(t, ValidateAWSRegion(region))
		})
	}

	invalid := []string{
		"",
		"us-east",
		"us-east-",
		"US-EAST-1",
		"useast1",
		"us-east-1.evil.example",
		"us-east-1/../../latest",
		"us-east-1:8080",
		" us-east-1",
		"us-east-1 ",
		"us-east-1\n",
		"../us-east-1",
	}
	for _, region := range invalid {
		t.Run("invalid_"+region, func(t *testing.T) {
			require.Error(t, ValidateAWSRegion(region))
		})
	}
}
