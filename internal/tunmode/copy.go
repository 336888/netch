package tunmode

import (
	"io"
	"net"
	"sync"
)

var pool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

func copyBuf(dst io.Writer, src io.Reader) (int64, error) {
	bp := pool.Get().(*[]byte)
	defer pool.Put(bp)
	return io.CopyBuffer(dst, src, *bp)
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
