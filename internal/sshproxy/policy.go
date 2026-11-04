package sshproxy

import (
	"errors"

	"golang.org/x/crypto/ssh"
)

var errCapabilityDenied = errors.New("SSH capability denied")

type requestDecision int

const (
	forwardRequest requestDecision = iota
	// dropRequest refuses client bookkeeping without auditing it.
	dropRequest
	refuseRequest
)

// sessionRequestPolicy is the default-deny allowlist for session channel
// requests. It returns the decision and the audited detail.
func sessionRequestPolicy(typ string, payload []byte) (requestDecision, string) {
	switch typ {
	case "exec":
		var p struct{ Command string }
		if ssh.Unmarshal(payload, &p) != nil {
			return refuseRequest, ""
		}
		return forwardRequest, p.Command
	case "subsystem", "signal":
		var p struct{ Name string }
		if ssh.Unmarshal(payload, &p) != nil || (typ == "subsystem" && p.Name != "sftp") {
			return refuseRequest, p.Name
		}
		return forwardRequest, p.Name
	case "env", "eow@openssh.com":
		// OpenSSH sends these routinely; environment injection stays blocked.
		return dropRequest, ""
	default:
		return refuseRequest, ""
	}
}
