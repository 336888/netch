package outbound

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/netchx/netch-go/internal/config"
)

type trojanDialer struct {
	server   string
	password string
	sni      string
	timeout  time.Duration
}

func newTrojan(s config.Server, timeout time.Duration) (Dialer, error) {
	sni := s.SNI
	if sni == "" {
		sni = s.Address
	}
	return &trojanDialer{
		server:   net.JoinHostPort(s.Address, strconv.Itoa(int(s.Port))),
		password: s.Password,
		sni:      sni,
		timeout:  timeout,
	}, nil
}

func (t *trojanDialer) Close() error { return nil }

func (t *trojanDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("trojan: unsupported network %s", network)
	}
	nd := net.Dialer{Timeout: t.timeout, KeepAlive: 30 * time.Second}
	raw, err := nd.DialContext(ctx, "tcp", t.server)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         t.sni,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})
	hctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(hctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("trojan: tls handshake: %w", err)
	}

	if err := t.writeRequest(tlsConn, addr); err != nil {
		tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (t *trojanDialer) writeRequest(c net.Conn, addr string) error {
	// hex(SHA224(password))
	sum := sha256.Sum224([]byte(t.password))
	hexPwd := make([]byte, 56)
	hex.Encode(hexPwd, sum[:])

	buf := make([]byte, 0, 64+len(addr)+8)
	buf = append(buf, hexPwd...)
	buf = append(buf, '\r', '\n')
	buf = append(buf, 0x01) // CMD connect

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, 0x03)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("trojan: hostname too long")
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(port>>8), byte(port))
	buf = append(buf, '\r', '\n')

	_, err = c.Write(buf)
	return err
}
