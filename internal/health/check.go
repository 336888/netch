// Package health probes each configured server and reports reachability.
package health

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/netchx/netch-go/internal/config"
)

// Status is the result of one probe.
type Status struct {
	Name    string
	OK      bool
	Latency time.Duration
	Err     string
	Checked time.Time
}

// CheckTCP measures the time to complete a TCP handshake with the server.
// A direct entry is always OK because there is nothing to dial.
func CheckTCP(ctx context.Context, s config.Server, timeout time.Duration) Status {
	st := Status{Name: s.Name, Checked: time.Now()}
	if s.Protocol == "direct" {
		st.OK = true
		return st
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(s.Address, fmt.Sprint(s.Port))
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		st.Err = err.Error()
		return st
	}
	_ = conn.Close()
	st.OK = true
	st.Latency = time.Since(start)
	return st
}

// Monitor probes every server on an interval and pushes a snapshot to onUpdate.
// Runs until ctx is cancelled.
func Monitor(ctx context.Context, servers []config.Server, interval time.Duration, timeout time.Duration, onUpdate func([]Status)) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	probeAll := func() {
		out := make([]Status, len(servers))
		var wg sync.WaitGroup
		wg.Add(len(servers))
		for i, srv := range servers {
			i, srv := i, srv
			go func() {
				defer wg.Done()
				out[i] = CheckTCP(ctx, srv, timeout)
			}()
		}
		wg.Wait()
		if onUpdate != nil {
			onUpdate(out)
		}
	}

	probeAll()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			probeAll()
		}
	}
}
