package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowimpl"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/netchx/netch-go/internal/config"
)

type shadowsocksDialer struct {
	server  string
	method  shadowsocks.Method
	timeout time.Duration
}

func newShadowsocks(s config.Server, timeout time.Duration) (Dialer, error) {
	method, err := shadowimpl.FetchMethod(s.Method, s.Password, nil)
	if err != nil {
		return nil, fmt.Errorf("ss: fetch method %q: %w", s.Method, err)
	}
	return &shadowsocksDialer{
		server:  net.JoinHostPort(s.Address, strconv.Itoa(int(s.Port))),
		method:  method,
		timeout: timeout,
	}, nil
}

func (s *shadowsocksDialer) Close() error { return nil }

func (s *shadowsocksDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("ss: unsupported network %s", network)
	}
	nd := net.Dialer{Timeout: s.timeout, KeepAlive: 30 * time.Second}
	raw, err := nd.DialContext(ctx, "tcp", s.server)
	if err != nil {
		return nil, err
	}
	dest := M.ParseSocksaddr(addr)
	c, err := s.method.DialConn(raw, dest)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("ss: handshake: %w", err)
	}
	return c, nil
}
