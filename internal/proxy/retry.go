package proxy

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"
)

// RetryPolicy controls how a failed dial is retried.
type RetryPolicy struct {
	Attempts int           // total tries including the first
	Backoff  time.Duration // base wait between tries
}

// DefaultRetry retries once after 150ms. Enough for a transient reset, short
// enough that the browser does not time out.
var DefaultRetry = RetryPolicy{Attempts: 2, Backoff: 150 * time.Millisecond}

// retryable reports whether another attempt might succeed. A refused
// connection means the target really is down, so retrying only wastes time.
func retryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTemporary || dnsErr.IsTimeout
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		// ECONNRESET and EPIPE often recover; ECONNREFUSED does not.
		if errors.Is(oe.Err, syscall.ECONNREFUSED) {
			return false
		}
		return true
	}
	return false
}

// dialWithRetry runs the dialer up to policy.Attempts times, backing off
// between attempts, and returns the last error if every try fails.
func dialWithRetry(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error),
	network, addr string, p RetryPolicy) (net.Conn, error) {

	if p.Attempts < 1 {
		p.Attempts = 1
	}
	var lastErr error
	for i := 0; i < p.Attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(p.Backoff * time.Duration(i)):
			}
		}
		c, err := dial(ctx, network, addr)
		if err == nil {
			return c, nil
		}
		lastErr = err
		if !retryable(err) {
			return nil, err
		}
	}
	return nil, lastErr
}
