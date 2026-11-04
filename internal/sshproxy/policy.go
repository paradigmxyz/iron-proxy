package sshproxy

import (
	"errors"
	"golang.org/x/crypto/ssh"
)

var errCapabilityDenied = errors.New("SSH capability denied")

func downstreamPolicy(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
	deny := func() (ssh.PipePacketHookMethod, []byte, error) {
		return ssh.PipePacketHookTransform, nil, errCapabilityDenied
	}
	if len(packet) == 0 {
		return deny()
	}
	switch packet[0] {
	case 80:
		return refuseGlobalRequest(packet)
	case 90:
		var open struct {
			Type      string
			Sender    uint32
			Window    uint32
			MaxPacket uint32
			Extra     []byte `ssh:"rest"`
		}
		if ssh.Unmarshal(packet[1:], &open) != nil || open.Type != "session" {
			return deny()
		}
	case 98:
		var req struct {
			Channel   uint32
			Type      string
			WantReply bool
			Payload   []byte `ssh:"rest"`
		}
		if ssh.Unmarshal(packet[1:], &req) != nil {
			return deny()
		}
		switch req.Type {
		case "exec", "signal":
		case "env", "eow@openssh.com":
			if req.WantReply {
				return deny()
			}
			// Ignore client bookkeeping without exposing environment injection.
			return ssh.PipePacketHookTransform, nil, nil
		case "subsystem":
			var sub struct{ Name string }
			if ssh.Unmarshal(req.Payload, &sub) != nil || sub.Name != "sftp" {
				return deny()
			}
		default:
			return deny()
		}
	}
	return ssh.PipePacketHookTransform, packet, nil
}

func upstreamPolicy(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(packet) == 0 || packet[0] == 90 {
		return ssh.PipePacketHookTransform, nil, errCapabilityDenied
	}
	if packet[0] == 80 {
		return refuseGlobalRequest(packet)
	}
	return ssh.PipePacketHookTransform, packet, nil
}

// Refuse globals locally, including forwarding and OpenSSH keepalives.
func refuseGlobalRequest(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
	var req struct {
		Type      string
		WantReply bool
		Payload   []byte `ssh:"rest"`
	}
	if ssh.Unmarshal(packet[1:], &req) != nil {
		return ssh.PipePacketHookTransform, nil, errCapabilityDenied
	}
	if req.WantReply {
		return ssh.PipePacketHookReply, []byte{82}, nil
	}
	return ssh.PipePacketHookTransform, nil, nil
}
