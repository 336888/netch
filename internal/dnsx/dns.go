// Package dnsx runs a local DNS server that resolves through the active
// upstream. Point the OS resolver at it to defeat plaintext DNS tampering.
package dnsx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

type Server struct {
	Listen   string
	Upstream []string
	Dialer   Dialer
	Logger   *slog.Logger
	Timeout  time.Duration
	Cache    *Cache
}

type Cache struct {
	mu      sync.RWMutex
	entries map[string]entry
	maxTTL  time.Duration
}

type entry struct {
	msg    *dns.Msg
	expire time.Time
}

func NewCache(maxTTL time.Duration) *Cache {
	if maxTTL <= 0 {
		maxTTL = 10 * time.Minute
	}
	return &Cache{entries: make(map[string]entry), maxTTL: maxTTL}
}

func (c *Cache) get(key string) (*dns.Msg, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expire) {
		return nil, false
	}
	return e.msg.Copy(), true
}

func (c *Cache) put(key string, msg *dns.Msg) {
	ttl := c.maxTTL
	if len(msg.Answer) > 0 {
		if d := time.Duration(msg.Answer[0].Header().Ttl) * time.Second; d > 0 && d < ttl {
			ttl = d
		}
	}
	c.mu.Lock()
	c.entries[key] = entry{msg: msg.Copy(), expire: time.Now().Add(ttl)}
	c.mu.Unlock()
}

func (s *Server) log() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}

func (s *Server) timeout() time.Duration {
	if s.Timeout <= 0 {
		return 5 * time.Second
	}
	return s.Timeout
}

func (s *Server) upstreams() []string {
	if len(s.Upstream) == 0 {
		return []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	out := make([]string, 0, len(s.Upstream))
	for _, u := range s.Upstream {
		if _, _, err := net.SplitHostPort(u); err != nil {
			u = net.JoinHostPort(u, "53")
		}
		out = append(out, u)
	}
	return out
}

// ListenAndServe starts UDP and TCP listeners and blocks until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Cache == nil {
		s.Cache = NewCache(10 * time.Minute)
	}
	addr := s.Listen
	if addr == "" {
		addr = "127.0.0.1:53"
	}

	handler := dns.HandlerFunc(s.handle)

	udpSrv := &dns.Server{Addr: addr, Net: "udp", Handler: handler}
	tcpSrv := &dns.Server{Addr: addr, Net: "tcp", Handler: handler}

	errCh := make(chan error, 2)
	go func() {
		if err := udpSrv.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("dns udp: %w", err)
		}
	}()
	go func() {
		if err := tcpSrv.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("dns tcp: %w", err)
		}
	}()

	s.log().Info("dns listening", "addr", addr, "upstream", s.upstreams())

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = udpSrv.ShutdownContext(shutCtx)
		_ = tcpSrv.ShutdownContext(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeFormatError))
		return
	}

	q := r.Question[0]
	key := cacheKey(q)

	if s.Cache != nil {
		if cached, ok := s.Cache.get(key); ok {
			cached.Id = r.Id
			_ = w.WriteMsg(cached)
			return
		}
	}

	resp, err := s.resolve(r)
	if err != nil {
		s.log().Debug("dns resolve", "q", q.Name, "type", dns.TypeToString[q.Qtype], "err", err)
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		return
	}
	resp.Id = r.Id

	if s.Cache != nil && len(resp.Answer) > 0 {
		s.Cache.put(key, resp)
	}
	_ = w.WriteMsg(resp)
}

func (s *Server) resolve(r *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout())
	defer cancel()

	var lastErr error
	for _, up := range s.upstreams() {
		// truncation or a blocked UDP path both fall back to TCP
		if resp, err := s.exchangeOn(ctx, "udp", up, r); err == nil && resp != nil {
			if resp.Truncated {
				if tresp, terr := s.exchangeOn(ctx, "tcp", up, r); terr == nil {
					return tresp, nil
				}
			}
			return resp, nil
		}
		if resp, err := s.exchangeOn(ctx, "tcp", up, r); err == nil && resp != nil {
			return resp, nil
		} else {
			lastErr = err
		}
	}
	return nil, errors.Join(lastErr, errors.New("dns: all upstreams failed"))
}

func (s *Server) exchangeOn(ctx context.Context, network, up string, r *dns.Msg) (*dns.Msg, error) {
	conn, err := s.dialContext(ctx, network, up)
	if err != nil {
		return nil, err
	}
	c := &dns.Client{Net: network, Timeout: s.timeout()}
	dc := &dns.Conn{Conn: conn, UDPSize: 1232}
	resp, _, err := c.ExchangeWithConn(r, dc)
	_ = conn.Close()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *Server) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.Dialer != nil {
		return s.Dialer(ctx, network, addr)
	}
	nd := net.Dialer{Timeout: s.timeout()}
	return nd.DialContext(ctx, network, addr)
}

func cacheKey(q dns.Question) string {
	return q.Name + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass]
}
