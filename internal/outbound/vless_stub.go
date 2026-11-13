//go:build !with_utls

package outbound

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/netchx/netch-go/internal/config"
)

// VLESS without the with_utls tag cannot speak REALITY. Build with
// -tags with_utls,with_gvisor for full support.
func newVLESS(s config.Server, timeout time.Duration) (Dialer, error) {
	return nil, errors.New("vless: build with -tags with_utls to enable REALITY")
}

type vlessDialer struct{}

func (v *vlessDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, errors.New("vless: not built")
}

func (v *vlessDialer) Close() error { return nil }
