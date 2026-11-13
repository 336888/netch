//go:build with_utls

package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	tls2 "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/netchx/netch-go/internal/config"
)

type vlessDialer struct {
	server  string
	timeout time.Duration
	client  *vless.Client
	reality tls2.Config
}

func newVLESS(s config.Server, timeout time.Duration) (Dialer, error) {
	if s.UUID == "" {
		return nil, fmt.Errorf("vless: uuid is required")
	}
	client, err := vless.NewClient(s.UUID, s.Flow, nil)
	if err != nil {
		return nil, fmt.Errorf("vless: new client: %w", err)
	}
	addr := net.JoinHostPort(s.Address, strconv.Itoa(int(s.Port)))
	d := &vlessDialer{server: addr, timeout: timeout, client: client}

	if s.Security == "reality" && s.PublicKey != "" {
		rc, rerr := tls2.NewRealityClient(
			context.Background(),
			nil,
			addr,
			option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: s.SNI,
				Reality: &option.OutboundRealityOptions{
					PublicKey: s.PublicKey,
					ShortID:   s.ShortID,
				},
				UTLS: &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: s.Fingerprint,
				},
			},
		)
		if rerr != nil {
			return nil, fmt.Errorf("vless: reality: %w", rerr)
		}
		d.reality = rc
	}
	return d, nil
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

	var conn net.Conn = raw
	if v.reality != nil {
		rc, ok := v.reality.(*tls2.RealityClientConfig)
		if !ok {
			raw.Close()
			return nil, fmt.Errorf("vless: unexpected reality config type %T", v.reality)
		}
		tlsConn, herr := rc.Client(raw)
		if herr != nil {
			raw.Close()
			return nil, fmt.Errorf("vless: reality handshake: %w", herr)
		}
		conn = tlsConn
	}

	dest := M.ParseSocksaddr(addr)
	c, err := v.client.DialConn(conn, dest)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless: handshake: %w", err)
	}
	return c, nil
}
