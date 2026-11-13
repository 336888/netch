// Package tunmode implements TUN mode on top of sing-tun's gVisor stack.
//
// Build with -tags with_gvisor, otherwise the stack constructor returns
// tun.ErrGVisorNotIncluded.
package tunmode

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/netchx/netch-go/internal/config"
)

type Options struct {
	Config   config.Tun
	Dialer   func(ctx context.Context, network, addr string) (net.Conn, error)
	Logger   any
	Inet4    netip.Prefix
	Inet6    netip.Prefix
	UDPTimeout time.Duration
}

// Run brings up the TUN device and pumps packets until ctx is cancelled.
func Run(ctx context.Context, o Options) error {
	if o.Dialer == nil {
		return errors.New("tunmode: dialer is required")
	}
	if o.Inet4 == (netip.Prefix{}) {
		o.Inet4 = netip.MustParsePrefix("198.18.0.1/16")
	}
	if o.UDPTimeout == 0 {
		o.UDPTimeout = 5 * time.Minute
	}

	name := o.Config.Name
	if name == "" {
		name = "Netch"
	}
	mtu := o.Config.MTU
	if mtu == 0 {
		mtu = 1500
	}
	stack := o.Config.Stack
	if stack == "" {
		stack = "gvisor"
	}

	tunOpts := tun.Options{
		Name:         name,
		MTU:          uint32(mtu),
		Inet4Address: []netip.Prefix{o.Inet4},
		AutoRoute:    o.Config.AutoRoute,
		StrictRoute:  true,
	}
	if o.Inet6 != (netip.Prefix{}) {
		tunOpts.Inet6Address = []netip.Prefix{o.Inet6}
	}

	dev, err := tun.New(tunOpts)
	if err != nil {
		return fmt.Errorf("tunmode: create device: %w", err)
	}
	defer dev.Close()

	h := &Handler{dialer: o.Dialer, udpTimeout: o.UDPTimeout}

	st, err := tun.NewStack(stack, tun.StackOptions{
		Context:    ctx,
		Tun:        dev,
		TunOptions: tunOpts,
		UDPTimeout: o.UDPTimeout,
		Handler:    h,
	})
	if err != nil {
		return fmt.Errorf("tunmode: create stack: %w", err)
	}
	defer st.Close()

	if err := st.Start(); err != nil {
		return fmt.Errorf("tunmode: start stack: %w", err)
	}

	<-ctx.Done()
	return nil
}

// Handler implements tun.Handler and forwards TCP flows to the upstream dialer.
type Handler struct {
	dialer     func(ctx context.Context, network, addr string) (net.Conn, error)
	udpTimeout time.Duration
}

func (h *Handler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(errors.New("done"))
	}

	up, err := h.dialer(ctx, "tcp", destination.String())
	if err != nil {
		return
	}
	defer up.Close()

	relay(conn, up)
}

func (h *Handler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	// Zero verdict: let the stack pick its default tracking.
	return tun.FlowVerdict{}
}

func (h *Handler) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	// Plain DNS over UDP is not wired; drop so clients fall back to TCP.
}

func (h *Handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	// UDP over TUN needs a full NAT table; leave it closed for now so the
	// caller sees an immediate failure instead of silent blackholing.
	if onClose != nil {
		onClose(errors.New("tunmode: udp not implemented"))
	}
	conn.Close()
}

// NewHandler builds a Handler with the given upstream dialer.
func NewHandler(dialer func(ctx context.Context, network, addr string) (net.Conn, error), udpTimeout time.Duration) *Handler {
	return &Handler{dialer: dialer, udpTimeout: udpTimeout}
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = copyBuf(b, a); done <- struct{}{} }()
	go func() { _, _ = copyBuf(a, b); done <- struct{}{} }()
	<-done
}
