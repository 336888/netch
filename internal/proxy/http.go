package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/netchx/netch-go/internal/connlog"
)

type HTTP struct {
	Addr    string
	Logger  *slog.Logger
	Timeout time.Duration
	Dialer  func(ctx context.Context, network, addr string) (net.Conn, error)
	Route   RouteFunc
	OnEvent func(connlog.Event)
}

func (h *HTTP) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              h.Addr,
		Handler:           http.HandlerFunc(h.handle),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http proxy %s: %w", h.Addr, err)
	}
	return nil
}

func (h *HTTP) log() *slog.Logger {
	if h.Logger == nil {
		return slog.Default()
	}
	return h.Logger
}

func (h *HTTP) dial() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if h.Dialer != nil {
		return h.Dialer
	}
	d := h.Timeout
	if d == 0 {
		d = 30 * time.Second
	}
	nd := net.Dialer{Timeout: d, KeepAlive: 30 * time.Second}
	return nd.DialContext
}

func (h *HTTP) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		h.forward(w, r)
		return
	}
	h.tunnel(w, r)
}

func (h *HTTP) tunnel(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var (
		up     net.Conn
		err    error
		action = "proxy"
	)
	if h.Route != nil {
		up, action, err = h.Route(r.Context(), "tcp", r.Host)
	} else {
		up, err = h.dial()(r.Context(), "tcp", r.Host)
	}
	if err != nil {
		if h.OnEvent != nil {
			h.OnEvent(connlog.Event{Time: start, Proto: "http", Action: "fail", Target: r.Host, Dur: time.Since(start), DurMs: time.Since(start).Milliseconds(), Err: err.Error()})
		}
		h.log().Debug("http connect", "host", r.Host, "err", err)
		http.Error(w, "connection failed", http.StatusBadGateway)
		return
	}
	defer up.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	sent, recv := Relay(client, up)
	if h.OnEvent != nil {
		h.OnEvent(connlog.Event{Time: start, Proto: "http", Action: action, Target: r.Host, Up: sent, Down: recv, Dur: time.Since(start), DurMs: time.Since(start).Milliseconds()})
	}
	h.log().Debug("http tunnel done", "host", r.Host, "sent", sent, "recv", recv)
}

func (h *HTTP) forward(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = r.Host
	}

	transport := &http.Transport{
		DialContext:           h.dial(),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	defer transport.CloseIdleConnections()

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		if h.OnEvent != nil {
			h.OnEvent(connlog.Event{Time: start, Proto: "http", Action: "fail", Target: outReq.URL.Host, Dur: time.Since(start), DurMs: time.Since(start).Milliseconds(), Err: err.Error()})
		}
		h.log().Debug("http forward", "url", outReq.URL.String(), "err", err)
		http.Error(w, "upstream failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	if h.OnEvent != nil {
		h.OnEvent(connlog.Event{Time: start, Proto: "http", Action: "proxy", Target: outReq.URL.Host, Down: n, Dur: time.Since(start), DurMs: time.Since(start).Milliseconds()})
	}
}
