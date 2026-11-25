package transform

import (
	"fmt"
	"regexp"
)

// awsRegionPattern matches AWS region names such as us-east-1,
// us-gov-west-1, cn-north-1, us-isob-east-1, and eusc-de-east-1: lowercase
// letters, digits and hyphens only, so a region can never change an
// endpoint's host.
var awsRegionPattern = regexp.MustCompile(`^[a-z]+(-[a-z0-9]+)+-[0-9]+$`)

// ValidateAWSRegion rejects a region string that cannot be a real AWS region
// name. AWS SDKs interpolate the region into endpoint hostnames, so accepting a
// free-form value would let configuration control where credentials are sent.
func ValidateAWSRegion(region string) error {
	if !awsRegionPattern.MatchString(region) {
		return fmt.Errorf("invalid AWS region %q", region)
	}
	return nil
}
