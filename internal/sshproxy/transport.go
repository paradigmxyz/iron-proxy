package sshproxy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/gobwas/ws"
	"github.com/ironsh/iron-proxy/internal/dnsguard"
)

func transport(ctx context.Context, target string, deny []string, roots *x509.CertPool) (net.Conn, error) {
	// Bound TLS and HTTP upgrade negotiation too, not only the TCP dial.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	u, err := url.Parse(target)
	if err != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid SSH destination")
	}
	guard, err := dnsguard.New(deny)
	if err != nil {
		return nil, errors.New("invalid upstream deny CIDRs")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: guard.DialControl}
	switch u.Scheme {
	case "tcp":
		if u.Path != "" {
			return nil, errors.New("invalid TCP destination")
		}
		return dialer.DialContext(ctx, "tcp", u.Host)
	case "wss":
		// wstunnel v11 carries the fixed loopback SSH target in a JWT subprotocol.
		token, err := tunnelToken()
		if err != nil {
			return nil, err
		}

		client := ws.Dialer{NetDial: dialer.DialContext, TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, Timeout: 10 * time.Second, Protocols: []string{"v1", "authorization.bearer." + token}}
		conn, buffered, handshake, err := client.Dial(ctx, target)
		if err != nil {
			return nil, errors.New("SSH WebSocket connection failed")
		}
		if handshake.Protocol != "v1" {
			_ = conn.Close()
			return nil, errors.New("unsupported SSH WebSocket protocol")
		}
		stream := &websocketConn{Conn: conn, reader: conn}
		if buffered != nil {
			prefix := make([]byte, buffered.Buffered())
			if _, err := io.ReadFull(buffered, prefix); err != nil {
				_ = conn.Close()
				return nil, err
			}
			ws.PutReader(buffered)
			stream.reader = io.MultiReader(bytes.NewReader(prefix), conn)
		}
		return stream, nil

	default:
		return nil, errors.New("SSH transport must be tcp or wss")
	}
}

func tunnelToken() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", errors.New("tunnel nonce unavailable")
	}
	payload, err := json.Marshal(map[string]any{"id": hex.EncodeToString(nonce), "p": map[string]any{"Tcp": map[string]any{"proxy_protocol": false}}, "r": "127.0.0.1", "rp": 22})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	text := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc.EncodeToString(payload)
	// wstunnel treats this JWT as routing metadata, not as authentication.
	mac := hmac.New(sha256.New, nonce)
	if _, err := mac.Write([]byte(text)); err != nil {
		return "", err
	}
	return text + "." + enc.EncodeToString(mac.Sum(nil)), nil
}
