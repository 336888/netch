package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/netchx/netch-go/internal/config"
)

type vlessDialer struct {
	server  string
	timeout time.Duration
	client  *vless.Client
}

func newVLESS(s config.Server, timeout time.Duration) (Dialer, error) {
	if s.UUID == "" {
		return nil, fmt.Errorf("vless: uuid is required")
	}
	client, err := vless.NewClient(s.UUID, "", nil)
	if err != nil {
		return nil, fmt.Errorf("vless: new client: %w", err)
	}
	return &vlessDialer{
		server:  net.JoinHostPort(s.Address, strconv.Itoa(int(s.Port))),
		timeout: timeout,
		client:  client,
	}, nil
}

func (v *vlessDialer) Close() error { return nil }

func (v *vlessDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("vless: unsupported network %s", network)
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
		return nil, fmt.Errorf("vless: handshake: %w", err)
	}
	return c, nil
}
