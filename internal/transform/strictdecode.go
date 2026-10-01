package transform

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// DecodeKnownFields decodes one transform config and rejects unknown YAML
// fields at every nested struct level. A misspelled security-policy field must
// never silently become its zero value.
func DecodeKnownFields(node yaml.Node, destination any) error {
	payload, err := yaml.Marshal(&node)
	if err != nil {
		return fmt.Errorf("encoding transform config for strict decode: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	decoder.KnownFields(true)
	return decoder.Decode(destination)
}
