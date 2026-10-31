package sshproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"testing"
	"time"
)

func TestWstunnelIntegration(t *testing.T) {
	target := os.Getenv("IRON_SSH_WSTUNNEL_TEST_URL")
	caPath := os.Getenv("IRON_SSH_WSTUNNEL_TEST_CA")
	if target == "" || caPath == "" {
		t.Skip("set IRON_SSH_WSTUNNEL_TEST_URL and IRON_SSH_WSTUNNEL_TEST_CA for a local OpenSSH/wstunnel fixture")
	}
	cert, err := os.ReadFile(caPath)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(cert))
	conn, err := transport(context.Background(), target, []string{}, roots)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	_, err = conn.Write([]byte("SSH-2.0-iron-test\r\n"))
	require.NoError(t, err)
	reader := bufio.NewReaderSize(conn, 256)
	banner, err := reader.ReadSlice('\n')
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(banner, []byte("SSH-2.0-")))
	// Wait for the packet header even when the banner spans multiple reads.
	var packetLength [4]byte
	_, err = io.ReadFull(reader, packetLength[:])
	require.NoError(t, err)
}
