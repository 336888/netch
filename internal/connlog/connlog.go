// Package connlog emits one event per proxied connection so users can watch
// traffic in real time instead of guessing from silence.
package connlog

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Time    time.Time     `json:"t"`
	Proto   string        `json:"proto"`
	Action  string        `json:"action"`
	Target  string        `json:"target"`
	Process string        `json:"proc,omitempty"`
	Rule    string        `json:"rule,omitempty"`
	Up      int64         `json:"up"`
	Down    int64         `json:"down"`
	Dur     time.Duration `json:"-"`
	DurMs   int64         `json:"dur_ms"`
	Err     string        `json:"err,omitempty"`
}

// Sink receives every event. Implementations must be safe for concurrent use.
type Sink interface {
	Emit(Event)
}

// Multi fans an event out to several sinks.
type Multi struct {
	sinks []Sink
}

func NewMulti(s ...Sink) *Multi { return &Multi{sinks: s} }

func (m *Multi) Emit(e Event) {
	for _, s := range m.sinks {
		s.Emit(e)
	}
}

// WriterSink formats events as one line each and writes them out immediately.
type WriterSink struct {
	mu     sync.Mutex
	w      io.Writer
	format string // "text" or "json"
}

func NewWriterSink(w io.Writer, format string) *WriterSink {
	if format == "" {
		format = "text"
	}
	return &WriterSink{w: w, format: format}
}

func (s *WriterSink) Emit(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.format == "json" {
		b, _ := json.Marshal(e)
		fmt.Fprintf(s.w, "%s\n", b)
		return
	}
	rule := ""
	if e.Rule != "" {
		rule = " rule=" + e.Rule
	}
	errPart := ""
	if e.Err != "" {
		errPart = " err=" + e.Err
	}
	fmt.Fprintf(s.w, "%s %-8s %-6s %-40s %6d毫秒 上行=%-7d 下行=%-7d%s%s\n",
		e.Time.Format("15:04:05.000"),
		e.Proto, actionLabel(e.Action), e.Target,
		e.DurMs, e.Up, e.Down, rule, errPart)
}

// ChanSink pushes formatted lines into a buffered channel for UI consumption.
// A full channel drops the line rather than blocking the proxy path.
type ChanSink struct {
	ch      chan string
	dropped atomic.Int64
}

func NewChanSink(size int) *ChanSink {
	if size <= 0 {
		size = 2048
	}
	return &ChanSink{ch: make(chan string, size)}
}

func (c *ChanSink) Emit(e Event) {
	line := fmt.Sprintf("%s %-8s %-6s %-40s %6d毫秒 上行=%-7d 下行=%-7d",
		e.Time.Format("15:04:05.000"), e.Proto, actionLabel(e.Action), e.Target, e.DurMs, e.Up, e.Down)
	if e.Err != "" {
		line += " err=" + e.Err
	}
	select {
	case c.ch <- line:
	default:
		c.dropped.Add(1)
	}
}

func (c *ChanSink) C() <-chan string { return c.ch }

func (c *ChanSink) Dropped() int64 { return c.dropped.Load() }

// Stats keeps running totals for the status bar.
type Stats struct {
	Total   atomic.Int64
	Proxied atomic.Int64
	Direct  atomic.Int64
	Rejected atomic.Int64
	Failed  atomic.Int64
	Up      atomic.Int64
	Down    atomic.Int64
}

func (s *Stats) Emit(e Event) {
	s.Total.Add(1)
	switch e.Action {
	case "proxy":
		s.Proxied.Add(1)
	case "direct":
		s.Direct.Add(1)
	case "reject":
		s.Rejected.Add(1)
	}
	if e.Err != "" {
		s.Failed.Add(1)
	}
	s.Up.Add(e.Up)
	s.Down.Add(e.Down)
}

func (s *Stats) Snapshot() (total, proxied, direct, rejected, failed, up, down int64) {
	return s.Total.Load(), s.Proxied.Load(), s.Direct.Load(), s.Rejected.Load(), s.Failed.Load(), s.Up.Load(), s.Down.Load()
}

// actionLabel renders the action in Chinese for the text sink. JSON keeps the
// raw value so scripts stay stable.
func actionLabel(a string) string {
	switch a {
	case "proxy":
		return "代理"
	case "direct":
		return "直连"
	case "reject":
		return "拒绝"
	case "fail":
		return "失败"
	}
	return a
}
