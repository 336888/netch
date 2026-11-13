package route

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Route struct {
	Prefix  netip.Prefix
	Gateway netip.Addr
	IfIndex int
}

func Add(ctx context.Context, r Route) error {
	switch runtime.GOOS {
	case "windows":
		return run(ctx, "route", "add", r.Prefix.String(), r.Gateway.String(), "metric", "1")
	case "linux":
		args := []string{"route", "add", r.Prefix.String(), "via", r.Gateway.String()}
		if r.IfIndex > 0 {
			args = append(args, "dev", fmt.Sprintf("%d", r.IfIndex))
		}
		return run(ctx, "ip", args...)
	default:
		return fmt.Errorf("route: unsupported os %s", runtime.GOOS)
	}
}

func Del(ctx context.Context, r Route) error {
	switch runtime.GOOS {
	case "windows":
		return run(ctx, "route", "delete", r.Prefix.String())
	case "linux":
		return run(ctx, "ip", "route", "del", r.Prefix.String())
	default:
		return fmt.Errorf("route: unsupported os %s", runtime.GOOS)
	}
}

// DefaultGateway returns the current default gateway address.
func DefaultGateway(ctx context.Context) (netip.Addr, error) {
	var out []byte
	var err error
	switch runtime.GOOS {
	case "windows":
		out, err = exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
			"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop").Output()
	case "linux":
		out, err = exec.CommandContext(ctx, "sh", "-c",
			"ip route show default | awk '/default/ {print $3; exit}'").Output()
	default:
		return netip.Addr{}, fmt.Errorf("route: unsupported os %s", runtime.GOOS)
	}
	if err != nil {
		return netip.Addr{}, err
	}
	s := strings.TrimSpace(string(out))
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse gateway %q: %w", s, err)
	}
	return addr, nil
}

func run(ctx context.Context, name string, args ...string) error {
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(c, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Join(err, fmt.Errorf("%s: %s", strings.Join(args, " "), strings.TrimSpace(string(out))))
	}
	return nil
}
