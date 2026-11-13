package connlog

import (
	"sync"
	"time"
)

// Ring keeps the most recent events for UI display.
type Ring struct {
	mu     sync.RWMutex
	buf    []Event
	head   int
	filled bool
	gen    uint64
}

// NewRing allocates a ring with the given capacity.
func NewRing(capacity int) *Ring {
	if capacity <= 0 {
		capacity = 500
	}
	return &Ring{buf: make([]Event, capacity)}
}

// Emit appends one event, overwriting the oldest when full.
func (r *Ring) Emit(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	r.mu.Lock()
	r.buf[r.head] = e
	r.head = (r.head + 1) % len(r.buf)
	if r.head == 0 {
		r.filled = true
	}
	r.gen++
	r.mu.Unlock()
}

// Snapshot returns the events oldest first.
func (r *Ring) Snapshot() []Event {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := r.head
	if r.filled {
		n = len(r.buf)
	}
	out := make([]Event, 0, n)
	start := 0
	if r.filled {
		start = r.head
	}
	for i := 0; i < n; i++ {
		out = append(out, r.buf[(start+i)%len(r.buf)])
	}
	return out
}

// Generation increments on every write. Callers use it to skip redundant
// table refreshes.
func (r *Ring) Generation() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.gen
}

// Len reports how many slots are in use.
func (r *Ring) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.filled {
		return len(r.buf)
	}
	return r.head
}
