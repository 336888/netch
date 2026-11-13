package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netchx/netch-go/internal/connlog"
)

const (
	socks5Version   = 0x05
	socks5NoAuth    = 0x00
	socks5UserPass  = 0x02
	socks5NoMethods = 0xFF

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded       = 0x00
	repGeneralFailure  = 0x01
	repHostUnreachable = 0x04
	repConnRefused     = 0x05
	repCmdNotSupported = 0x07
	repAddrNotSupported = 0x08
)

type Socks5 struct {
	Addr      string
	Username  string
	Password  string
	Logger    *slog.Logger
	Timeout   time.Duration
	Dialer    func(ctx context.Context, network, addr string) (net.Conn, error)
	Route     RouteFunc
	OnEvent   func(connlog.Event)

	// MaxConns caps concurrent client connections. Zero means unlimited.
	MaxConns int

	connCount atomic.Int64
	wg        sync.WaitGroup
}

func (s *Socks5) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("socks5 listen %s: %w", s.Addr, err)
	}
	return s.Serve(ctx, ln)
}

func (s *Socks5) Serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff < time.Second {
				backoff *= 2
			}
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, c)
		}()
	}
}

// Shutdown waits for in-flight connections to finish, up to timeout.
func (s *Socks5) Shutdown(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

func (s *Socks5) log() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}

func (s *Socks5) dialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.Dialer != nil {
		return s.Dialer
	}
	d := time.Duration(s.Timeout)
	if d == 0 {
		d = 30 * time.Second
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		nd := net.Dialer{Timeout: d, KeepAlive: 30 * time.Second}
		return nd.DialContext(ctx, network, addr)
	}
}

func (s *Socks5) handle(ctx context.Context, c net.Conn) {
	defer c.Close()

	if s.MaxConns > 0 {
		if s.connCount.Load() >= int64(s.MaxConns) {
			s.log().Warn("socks5 connection limit reached", "limit", s.MaxConns)
			return
		}
	}
	s.connCount.Add(1)
	defer s.connCount.Add(-1)

	start := time.Now()
	var (
		target string
		sent   int64
		recv   int64
		failErr error
		action  = "proxy"
	)
	defer func() {
		if s.OnEvent != nil {
			ev := connlog.Event{
				Time:  start,
				Proto: "socks5",
				Action: action,
				Target: target,
				Up:     sent,
				Down:   recv,
				Dur:    time.Since(start),
				DurMs:  time.Since(start).Milliseconds(),
			}
			if failErr != nil {
				ev.Err = failErr.Error()
				ev.Action = "fail"
			}
			s.OnEvent(ev)
		}
	}()

	// whole handshake must finish inside the timeout; stalls get dropped
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	if err := s.handshake(c); err != nil {
		failErr = err
		s.log().Debug("socks5 handshake", "err", err, "peer", c.RemoteAddr())
		return
	}

	var cmd byte
	var err error
	target, cmd, err = s.request(c)
	if err != nil {
		failErr = err
		s.log().Debug("socks5 request", "err", err, "peer", c.RemoteAddr())
		return
	}

	if cmd == cmdUDPAssociate {
		if err := s.handleUDP(ctx, c); err != nil {
			s.log().Debug("socks5 udp", "err", err)
		}
		return
	}

	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var up net.Conn
	if s.Route != nil {
		up, action, err = s.Route(dctx, "tcp", target)
	} else {
		up, err = s.dialer()(dctx, "tcp", target)
	}
	if err != nil {
		failErr = err
		s.reply(c, dialErrCode(err), netip.AddrPort{})
		return
	}
	defer up.Close()

	var bnd netip.AddrPort
	if ta, ok := up.LocalAddr().(*net.TCPAddr); ok {
		bnd = ta.AddrPort()
	}
	if err := s.reply(c, repSucceeded, bnd); err != nil {
		return
	}

	_ = c.SetDeadline(time.Time{})
	sent, recv = Relay(c, up)
	s.log().Debug("socks5 done", "target", target, "sent", sent, "recv", recv)
}

func (s *Socks5) handshake(c net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if head[0] != socks5Version {
		return fmt.Errorf("unsupported version %d", head[0])
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}

	want := byte(socks5NoAuth)
	if s.Username != "" {
		want = socks5UserPass
	}
	if !containsByte(methods, want) {
		_, _ = c.Write([]byte{socks5Version, socks5NoMethods})
		return errors.New("no acceptable auth method")
	}
	if _, err := c.Write([]byte{socks5Version, want}); err != nil {
		return err
	}
	if want == socks5UserPass {
		return s.authUserPass(c)
	}
	return nil
}

func (s *Socks5) authUserPass(c net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if head[0] != 0x01 {
		return fmt.Errorf("unsupported auth version %d", head[0])
	}
	user := make([]byte, head[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return err
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(c, pass); err != nil {
		return err
	}
	if string(user) != s.Username || string(pass) != s.Password {
		_, _ = c.Write([]byte{0x01, 0x01})
		return errors.New("bad credentials")
	}
	_, err := c.Write([]byte{0x01, 0x00})
	return err
}

func (s *Socks5) request(c net.Conn) (string, byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return "", 0, err
	}
	if head[0] != socks5Version {
		return "", 0, fmt.Errorf("bad request version %d", head[0])
	}
	cmd := head[1]

	var host string
	switch head[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", 0, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		return "", 0, fmt.Errorf("bad atyp %d", head[3])
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(pb)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), cmd, nil
}

func (s *Socks5) reply(c net.Conn, rep byte, bnd netip.AddrPort) error {
	buf := []byte{socks5Version, rep, 0x00}
	if bnd.IsValid() && bnd.Addr().Is4() {
		a := bnd.Addr().As4()
		buf = append(buf, atypIPv4)
		buf = append(buf, a[:]...)
	} else if bnd.IsValid() && bnd.Addr().Is6() {
		a := bnd.Addr().As16()
		buf = append(buf, atypIPv6)
		buf = append(buf, a[:]...)
	} else {
		buf = append(buf, atypIPv4, 0, 0, 0, 0)
	}
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, bnd.Port())
	buf = append(buf, p...)
	_, err := c.Write(buf)
	return err
}

func dialErrCode(err error) byte {
	var oe *net.OpError
	if errors.As(err, &oe) {
		var se *os.SyscallError
		if errors.As(oe.Err, &se) {
			switch se.Err.Error() {
			case "connection refused":
				return repConnRefused
			case "no route to host", "network is unreachable":
				return repHostUnreachable
			}
		}
	}
	return repGeneralFailure
}

func containsByte(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}
