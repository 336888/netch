//go:build linux

// Package processmode implements Process mode on Linux through nftables
// redirect managed by sing-tun's AutoRedirect.
package processmode

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/sagernet/sing-tun"
	tunmode "github.com/netchx/netch-go/internal/tunmode"
)

type Options struct {
	Dialer     func(ctx context.Context, network, addr string) (net.Conn, error)
	TableName  string
	UDPTimeout time.Duration
}

// Run installs the redirect rules and pumps connections until ctx is cancelled.
// Requires CAP_NET_ADMIN (root).
func Run(ctx context.Context, o Options) error {
	if o.Dialer == nil {
		return fmt.Errorf("processmode: dialer is required")
	}
	if o.TableName == "" {
		o.TableName = "netch"
	}
	if o.UDPTimeout == 0 {
		o.UDPTimeout = 5 * time.Minute
	}

	h := tunmode.NewHandler(o.Dialer, o.UDPTimeout)

	ar, err := tun.NewAutoRedirect(tun.AutoRedirectOptions{
		Context:   ctx,
		Handler:   h,
		TableName: o.TableName,
	})
	if err != nil {
		return fmt.Errorf("processmode: create redirect: %w", err)
	}
	if err := ar.Start(); err != nil {
		return fmt.Errorf("processmode: start redirect: %w", err)
	}
	defer ar.Close()

	<-ctx.Done()
	return nil
}
