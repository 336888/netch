package outbound

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/netchx/netch-go/internal/config"
)

type socks5Upstream struct {
	server   string
	username string
	password string
	timeout  time.Duration
}

func newSocks5Upstream(s config.Server, timeout time.Duration) (Dialer, error) {
	return &socks5Upstream{
		server:   net.JoinHostPort(s.Address, strconv.Itoa(int(s.Port))),
		username: s.Username,
		password: s.Password,
		timeout:  timeout,
	}, nil
}

func (s *socks5Upstream) Close() error { return nil }

func (s *socks5Upstream) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("socks5 upstream: unsupported network %s", network)
	}
	nd := net.Dialer{Timeout: s.timeout, KeepAlive: 30 * time.Second}
	c, err := nd.DialContext(ctx, "tcp", s.server)
	if err != nil {
		return nil, err
	}
	if err := s.handshake(c, addr); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (s *socks5Upstream) handshake(c net.Conn, addr string) error {
	_ = c.SetDeadline(time.Now().Add(s.timeout))

	method := byte(0x00)
	if s.username != "" {
		method = 0x02
	}
	if _, err := c.Write([]byte{0x05, 0x01, method}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 {
		return errors.New("socks5: bad version")
	}
	if reply[1] == 0xFF {
		return errors.New("socks5: no acceptable auth")
	}
	if reply[1] == 0x02 {
		if err := s.auth(c); err != nil {
			return err
		}
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("socks5: hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	req = append(req, pb...)

	if _, err := c.Write(req); err != nil {
		return err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5: connect failed code %d", head[1])
	}
	switch head[3] {
	case 0x01:
		_, err = io.ReadFull(c, make([]byte, 4+2))
	case 0x04:
		_, err = io.ReadFull(c, make([]byte, 16+2))
	case 0x03:
		l := make([]byte, 1)
		if _, err = io.ReadFull(c, l); err == nil {
			_, err = io.ReadFull(c, make([]byte, int(l[0])+2))
		}
	}
	if err != nil {
		return err
	}
	_ = c.SetDeadline(time.Time{})
	return nil
}

func (s *socks5Upstream) auth(c net.Conn) error {
	buf := []byte{0x01, byte(len(s.username))}
	buf = append(buf, s.username...)
	buf = append(buf, byte(len(s.password)))
	buf = append(buf, s.password...)
	if _, err := c.Write(buf); err != nil {
		return err
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil {
		return err
	}
	if r[1] != 0x00 {
		return errors.New("socks5: bad credentials")
	}
	return nil
}
