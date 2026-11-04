package sshproxy

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestSessionRequestPolicy(t *testing.T) {
	name := func(s string) []byte { return ssh.Marshal(struct{ Name string }{s}) }
	cases := []struct {
		typ      string
		payload  []byte
		decision requestDecision
		detail   string
	}{
		{"exec", ssh.Marshal(struct{ Command string }{"ls -la"}), forwardRequest, "ls -la"},
		{"exec", append(ssh.Marshal(struct{ Command string }{"ls"}), 0), refuseRequest, ""},
		{"subsystem", name("sftp"), forwardRequest, "sftp"},
		{"subsystem", name("netconf"), refuseRequest, "netconf"},
		{"signal", name("TERM"), forwardRequest, "TERM"},
		{"env", nil, dropRequest, ""},
		{"eow@openssh.com", nil, dropRequest, ""},
		{"shell", nil, refuseRequest, ""},
		{"pty-req", nil, refuseRequest, ""},
		{"x11-req", nil, refuseRequest, ""},
		{"auth-agent-req@openssh.com", nil, refuseRequest, ""},
	}
	for _, tc := range cases {
		t.Run(tc.typ+"/"+tc.detail, func(t *testing.T) {
			decision, detail := sessionRequestPolicy(tc.typ, tc.payload)
			require.Equal(t, tc.decision, decision)
			require.Equal(t, tc.detail, detail)
		})
	}
}
