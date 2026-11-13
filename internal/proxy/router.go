package proxy

import (
	"context"
	"net"
	"strconv"
)

// RouteFunc decides how a single connection should be handled.
// The action string is recorded in connection logs ("proxy", "direct", "reject").
type RouteFunc func(ctx context.Context, network, addr string) (net.Conn, string, error)

// DirectRoute builds a RouteFunc that ignores rules and always dials out.
func DirectRoute(dial func(ctx context.Context, network, addr string) (net.Conn, error)) RouteFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, string, error) {
		c, err := dial(ctx, network, addr)
		return c, "proxy", err
	}
}

// SplitAddr pulls host and port out of "host:port".
func SplitAddr(addr string) (string, uint16) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	p, _ := strconv.Atoi(portStr)
	return host, uint16(p)
}
