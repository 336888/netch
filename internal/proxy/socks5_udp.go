package proxy

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// udpSession keeps one upstream UDP socket per destination so a game or voice
// stream does not pay a dial per datagram.
type udpSession struct {
	mu    sync.Mutex
	conns map[string]*udpEntry
}

type udpEntry struct {
	conn *net.UDPConn
	seen time.Time
}

func newUDPSession() *udpSession {
	return &udpSession{conns: make(map[string]*udpEntry)}
}

func (u *udpSession) get(key string, dst *net.UDPAddr) (*net.UDPConn, error) {
	u.mu.Lock()
	if e, ok := u.conns[key]; ok {
		e.seen = time.Now()
		u.mu.Unlock()
		return e.conn, nil
	}
	u.mu.Unlock()

	conn, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		return nil, err
	}
	u.mu.Lock()
	u.conns[key] = &udpEntry{conn: conn, seen: time.Now()}
	u.mu.Unlock()
	return conn, nil
}

// reap closes sockets that have been idle longer than the cutoff.
func (u *udpSession) reap(idle time.Duration) {
	cutoff := time.Now().Add(-idle)
	u.mu.Lock()
	for k, e := range u.conns {
		if e.seen.Before(cutoff) {
			_ = e.conn.Close()
			delete(u.conns, k)
		}
	}
	u.mu.Unlock()
}

func (u *udpSession) close() {
	u.mu.Lock()
	for k, e := range u.conns {
		_ = e.conn.Close()
		delete(u.conns, k)
	}
	u.mu.Unlock()
}

// handleUDP implements the UDP ASSOCIATE command: open a local socket, tell the
// client its address, then relay datagrams with per-target socket reuse.
func (s *Socks5) handleUDP(ctx context.Context, c net.Conn) error {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer pc.Close()

	local := pc.LocalAddr().(*net.UDPAddr)
	bnd := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(local.Port))
	if err := s.reply(c, repSucceeded, bnd); err != nil {
		return err
	}

	sess := newUDPSession()
	defer sess.close()

	var clientMu sync.Mutex
	var clientAddr string

	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				sess.reap(2 * time.Minute)
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(90 * time.Second))
		n, from, rerr := pc.ReadFromUDP(buf)
		if rerr != nil {
			close(stop)
			return nil
		}
		clientMu.Lock()
		if clientAddr == "" {
			clientAddr = from.String()
		}
		isClient := from.String() == clientAddr
		clientMu.Unlock()
		if !isClient {
			continue
		}
		s.relayUDPOut(pc, sess, buf[:n])
	}
}

// relayUDPOut strips the SOCKS5 header, forwards the payload, and writes the
// reply back in the same framing.
func (s *Socks5) relayUDPOut(pc *net.UDPConn, sess *udpSession, pkt []byte) {
	if len(pkt) < 4 {
		return
	}
	atyp := pkt[3]
	var (
		host string
		off  int
	)
	switch atyp {
	case atypIPv4:
		if len(pkt) < 10 {
			return
		}
		host = net.IP(pkt[4:8]).String()
		off = 8
	case atypIPv6:
		if len(pkt) < 22 {
			return
		}
		host = net.IP(pkt[4:20]).String()
		off = 20
	case atypDomain:
		if len(pkt) < 5 {
			return
		}
		l := int(pkt[4])
		if len(pkt) < 7+l {
			return
		}
		host = string(pkt[5 : 5+l])
		off = 5 + l
	default:
		return
	}
	if len(pkt) < off+2 {
		return
	}
	port := binary.BigEndian.Uint16(pkt[off : off+2])
	payload := pkt[off+2:]

	dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return
	}
	key := dst.String()
	conn, err := sess.get(key, dst)
	if err != nil {
		return
	}

	if _, err := conn.Write(payload); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 65535)
	n, err := conn.Read(reply)
	if err != nil {
		return
	}

	out := make([]byte, 0, n+22)
	out = append(out, 0, 0, 0)
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		out = append(out, atypIPv4)
		out = append(out, ip.To4()...)
	} else {
		out = append(out, atypDomain, byte(len(host)))
		out = append(out, host...)
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	out = append(out, pb...)
	out = append(out, reply[:n]...)

	_, _ = pc.WriteToUDP(out, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}
