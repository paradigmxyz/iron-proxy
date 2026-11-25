package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// tenantTypes are the only `type` values a tenant config may use, in a
// secrets entry's source or anywhere in a transform's config: the source
// types that resolve from the control plane or from a secret backend the
// operator configured for tenants, and the workload identity provider. Any
// other type (env, file, vault_kv, or one added later) would read the
// shared proxy's own environment, disk or credentials, so it is refused.
var tenantTypes = map[string]bool{
	"control_plane":     true,
	"tenant_token":      true,
	"1password":         true,
	"1password_connect": true,
	"aws_sm":            true,
	"aws_ssm":           true,
	"workload_identity": true,
}

// tenantTransforms are the only transforms a tenant config may carry: the
// credential transforms. Others (grpc, annotate, judge, ...) could forward
// or record a request after the operator's own transforms injected secrets
// into it.
var tenantTransforms = map[string]bool{
	"oauth_token":  true,
	"gcp_auth":     true,
	"gcp_id_token": true,
	"aws_auth":     true,
	"hmac_sign":    true,
}

// RestrictTenantSources rewrites a control-plane secrets/transforms payload
// for tenancy mode. It drops (and returns the indices/names of) every secrets
// entry whose source type is not allowed for tenants (see tenantTypes), and
// every transform credential that uses such a type or GCP `keyfile_path`.
// Only the transforms in tenantTransforms are kept.
//
// Every check reads exact keys, and every kept entry is re-encoded from the
// value that was checked, so the pipeline is built from exactly what passed
// (duplicate or case-variant keys cannot make the builder see a different
// type than the check did).
func RestrictTenantSources(secrets, transforms json.RawMessage) (json.RawMessage, json.RawMessage, []string, error) {
	restrictedSecrets, reasons, err := restrictSecretEntries(secrets)
	if err != nil {
		return nil, nil, nil, err
	}
	restrictedTransforms, transformReasons, err := restrictTransformEntries(transforms)
	if err != nil {
		return nil, nil, nil, err
	}
	return restrictedSecrets, restrictedTransforms, append(reasons, transformReasons...), nil
}

func restrictSecretEntries(raw json.RawMessage) (json.RawMessage, []string, error) {
	if !jsonValuePresent(raw) {
		return raw, nil, nil
	}

	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, nil, fmt.Errorf("parsing secrets: %w", err)
	}

	kept := make([]any, 0, len(entries))
	var reasons []string
	for i, entry := range entries {
		if !jsonValuePresent(entry) {
			continue
		}
		obj, err := decodeJSONObject(entry)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing secrets[%d]: %w", i, err)
		}
		if reason, found := findDisallowedSource(obj, fmt.Sprintf("secrets[%d]", i)); found {
			reasons = append(reasons, reason)
			continue
		}
		kept = append(kept, obj)
	}

	out, err := json.Marshal(kept)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling secrets: %w", err)
	}
	return out, reasons, nil
}

func restrictTransformEntries(raw json.RawMessage) (json.RawMessage, []string, error) {
	if !jsonValuePresent(raw) {
		return raw, nil, nil
	}

	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, nil, fmt.Errorf("parsing transforms: %w", err)
	}

	kept := make([]any, 0, len(entries))
	var reasons []string
	for i, entry := range entries {
		if !jsonValuePresent(entry) {
			continue
		}
		var meta struct {
			Name   string          `json:"name"`
			Config json.RawMessage `json:"config"`
		}
		if err := json.Unmarshal(entry, &meta); err != nil {
			return nil, nil, fmt.Errorf("parsing transforms[%d]: %w", i, err)
		}
		if !tenantTransforms[meta.Name] {
			reasons = append(reasons, fmt.Sprintf("transforms[%d] (%s): transform is not allowed for tenants", i, meta.Name))
			continue
		}
		if !jsonValuePresent(meta.Config) {
			kept = append(kept, map[string]any{"name": meta.Name})
			continue
		}

		cfg, err := decodeJSONObject(meta.Config)
		if err != nil {
			return nil, nil, fmt.Errorf("transforms[%d] (%s): parsing config: %w", i, meta.Name, err)
		}
		if configHasKey(cfg, "keyfile_path") {
			reasons = append(reasons, fmt.Sprintf("transforms[%d] (%s): config sets keyfile_path", i, meta.Name))
			continue
		}

		if meta.Name == "oauth_token" {
			tokens, _ := cfg["tokens"].([]any)
			keptTokens := make([]any, 0, len(tokens))
			dropped := 0
			for j, tok := range tokens {
				if reason, found := findDisallowedSource(tok, fmt.Sprintf("tokens[%d]", j)); found {
					reasons = append(reasons, fmt.Sprintf("transforms[%d] (%s): %s", i, meta.Name, reason))
					dropped++
					continue
				}
				keptTokens = append(keptTokens, tok)
			}
			if dropped > 0 && len(keptTokens) == 0 {
				continue
			}
			cfg["tokens"] = keptTokens
		}
		if reason, found := findDisallowedSource(cfg, "config"); found {
			reasons = append(reasons, fmt.Sprintf("transforms[%d] (%s): %s", i, meta.Name, reason))
			continue
		}

		kept = append(kept, map[string]any{"name": meta.Name, "config": cfg})
	}

	out, err := json.Marshal(kept)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling transforms: %w", err)
	}
	return out, reasons, nil
}

func jsonValuePresent(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func decodeJSONObject(raw json.RawMessage) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config is not a JSON object")
	}
	return obj, nil
}

func configHasKey(v any, key string) bool {
	switch x := v.(type) {
	case map[string]any:
		if _, ok := x[key]; ok {
			return true
		}
		for _, child := range x {
			if configHasKey(child, key) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if configHasKey(child, key) {
				return true
			}
		}
	}
	return false
}

func findDisallowedSource(v any, path string) (string, bool) {
	switch x := v.(type) {
	case map[string]any:
		if typ, ok := x["type"].(string); ok && !tenantTypes[typ] {
			return fmt.Sprintf("%s uses disallowed source type %q", path, typ), true
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			childPath := path + "." + k
			if path == "" {
				childPath = k
			}
			if reason, found := findDisallowedSource(x[k], childPath); found {
				return reason, true
			}
		}
	case []any:
		for i, child := range x {
			if reason, found := findDisallowedSource(child, fmt.Sprintf("%s[%d]", path, i)); found {
				return reason, true
			}
		}
	}
	return "", false
}
