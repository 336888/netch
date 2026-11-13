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

// Relay copies bytes both ways and half-closes each side when the peer finishes.
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

func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.SetReadDeadline(time.Now())
}
