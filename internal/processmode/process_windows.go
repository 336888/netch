//go:build windows

package processmode

import (
	"context"
	"errors"
	"net"
	"time"
)

type Options struct {
	Dialer     func(ctx context.Context, network, addr string) (net.Conn, error)
	TableName  string
	UDPTimeout time.Duration
}

// Run needs WinDivert on Windows, which is a separate driver install.
func Run(ctx context.Context, o Options) error {
	return errors.New("processmode: windows requires WinDivert, not wired yet")
}
