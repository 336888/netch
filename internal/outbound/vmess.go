package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/netchx/netch-go/internal/config"
)

type vmessDialer struct {
	server   string
	timeout  time.Duration
	client   *vmess.Client
}

func newVMess(s config.Server, timeout time.Duration) (Dialer, error) {
	if s.UUID == "" {
		return nil, fmt.Errorf("vmess: uuid is required")
	}
	sec := s.Method
	if sec == "" {
		sec = "auto"
	}
	client, err := vmess.NewClient(s.UUID, sec, 0)
	if err != nil {
		return nil, fmt.Errorf("vmess: new client: %w", err)
	}
	return &vmessDialer{
		server:  net.JoinHostPort(s.Address, strconv.Itoa(int(s.Port))),
		timeout: timeout,
		client:  client,
	}, nil
}

func (v *vmessDialer) Close() error { return nil }

func (v *vmessDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("vmess: unsupported network %s", network)
	}
	nd := net.Dialer{Timeout: v.timeout, KeepAlive: 30 * time.Second}
	raw, err := nd.DialContext(ctx, "tcp", v.server)
	if err != nil {
		return nil, err
	}
	dest := M.ParseSocksaddr(addr)
	c, err := v.client.DialConn(raw, dest)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("vmess: handshake: %w", err)
	}
	return c, nil
}
