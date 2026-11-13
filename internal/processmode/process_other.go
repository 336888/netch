//go:build !linux && !windows

package processmode

import (
	"context"
	"errors"
	"net"
	"runtime"
	"time"
)

type Options struct {
	Dialer     func(ctx context.Context, network, addr string) (net.Conn, error)
	TableName  string
	UDPTimeout time.Duration
}

func Run(ctx context.Context, o Options) error {
	return errors.New("processmode: not supported on " + runtime.GOOS)
}
