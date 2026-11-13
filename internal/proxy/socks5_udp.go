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

// handleUDP implements the UDP ASSOCIATE command. It opens a local UDP socket,
// tells the client its address, then relays datagrams in both directions.
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

	var clientMu sync.Mutex
	var clientAddr string

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
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
			s.relayUDPOut(pc, buf[:n])
		}
	}()

	// Keep the TCP control connection alive; closing it ends the association.
	buf := make([]byte, 1)
	_, _ = c.Read(buf)
	<-done
	return nil
}

// relayUDPOut strips the SOCKS5 UDP header, forwards the payload, and writes
// the reply back in the same framing.
func (s *Socks5) relayUDPOut(pc *net.UDPConn, pkt []byte) {
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
	target, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		return
	}
	defer target.Close()

	_, _ = target.Write(payload)
	_ = target.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 65535)
	n, err := target.Read(reply)
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
