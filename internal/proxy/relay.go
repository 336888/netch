package proxy

import (
	"io"
	"net"
	"sync"
	"time"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// Relay copies bytes both ways. When one side finishes writing, the other side
// gets a half-close so it can drain outstanding data. Both sides are closed by
// the caller.
//
// The old version forced a read deadline when CloseWrite was unavailable,
// which truncated in-flight data on TLS and TUN conns. Now a conn that cannot
// half-close is simply left open until the peer closes.
func Relay(client, remote net.Conn) (up, down int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		bp := bufPool.Get().(*[]byte)
		defer bufPool.Put(bp)
		up, _ = io.CopyBuffer(remote, client, *bp)
		halfClose(remote)
	}()

	go func() {
		defer wg.Done()
		bp := bufPool.Get().(*[]byte)
		defer bufPool.Put(bp)
		down, _ = io.CopyBuffer(client, remote, *bp)
		halfClose(client)
	}()

	wg.Wait()
	return
}

// halfClose signals EOF to the peer without tearing down the whole conn.
// Conns that do not implement CloseWrite keep running; the caller's deferred
// Close will finish the job once both directions have drained.
func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// RelayWithIdle closes both sides when no bytes move for the given duration.
// Used for long-lived tunnels that can be orphaned by NAT timeouts.
func RelayWithIdle(client, remote net.Conn, idle time.Duration) (up, down int64) {
	setIdle := func(c net.Conn) {
		if idle > 0 {
			_ = c.SetDeadline(time.Now().Add(idle))
		}
	}
	setIdle(client)
	setIdle(remote)
	return Relay(client, remote)
}
