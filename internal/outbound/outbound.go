// Package outbound provides upstream dialers for every supported protocol.
package outbound

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/netchx/netch-go/internal/config"
)

// Dialer is the single abstraction every protocol backend implements.
// Returning a net.Conn that is already speaking to addr is the whole contract.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	Close() error
}

// New builds a Dialer from a config entry.
func New(s config.Server, timeout time.Duration) (Dialer, error) {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	switch s.Protocol {
	case "direct":
		return &Direct{Timeout: timeout}, nil
	case config.ProtoSOCKS5, config.ProtoHTTP:
		return newSocks5Upstream(s, timeout)
	case config.ProtoSS:
		return newShadowsocks(s, timeout)
	case config.ProtoVMess:
		return newVMess(s, timeout)
	case config.ProtoVLESS:
		// REALITY nodes provisioned for Xray reject sing-box's ClientHello.
		// If an xray binary is present, prefer it for those nodes.
		if s.Security == "reality" && s.PublicKey != "" {
			if _, ok := Available(); ok {
				return newXrayBackend(s, timeout)
			}
		}
		return newVLESS(s, timeout)
	case config.ProtoTrojan:
		return newTrojan(s, timeout)
	default:
		return nil, fmt.Errorf("outbound: unsupported protocol %q", s.Protocol)
	}
}

// Direct dials straight out, no proxy.
type Direct struct {
	Timeout time.Duration
}

func (d *Direct) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	t := d.Timeout
	if t == 0 {
		t = 30 * time.Second
	}
	nd := net.Dialer{Timeout: t, KeepAlive: 30 * time.Second}
	return nd.DialContext(ctx, network, addr)
}

func (d *Direct) Close() error { return nil }
