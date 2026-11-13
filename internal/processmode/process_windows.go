//go:build windows

package processmode

import (
	"context"
	"net"
	"time"

	"github.com/netchx/netch-go/internal/rule"
)

// Options configures Process mode.
type Options struct {
	Dialer     func(ctx context.Context, network, addr string) (net.Conn, error)
	TableName  string
	UDPTimeout time.Duration
	Matcher    *rule.Matcher
}

// Run delegates to WinDivert when a matcher is provided, otherwise returns a
// clear error so the caller knows what is missing.
func Run(ctx context.Context, o Options) error {
	return RunWinDivert(ctx, WinDivertOptions{Matcher: o.Matcher})
}
