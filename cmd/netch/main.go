package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync/atomic"
	"runtime"
	"syscall"
	"time"

	"github.com/netchx/netch-go/internal/config"
	"github.com/netchx/netch-go/internal/connlog"
	"github.com/netchx/netch-go/internal/dnsx"
	"github.com/netchx/netch-go/internal/rule"
	"github.com/netchx/netch-go/internal/gui"
	"github.com/netchx/netch-go/internal/logx"
	"github.com/netchx/netch-go/internal/outbound"
	"github.com/netchx/netch-go/internal/processmode"
	"github.com/netchx/netch-go/internal/sub"
	"github.com/netchx/netch-go/internal/sysproxy"
	"github.com/netchx/netch-go/internal/tunmode"
	"github.com/netchx/netch-go/internal/proxy"
)

var version = "dev"

func main() {
	var (
		cfgPath = flag.String("c", "config.json", "path to config file")
		showVer = flag.Bool("version", false, "print version and exit")
		useGUI  = flag.Bool("gui", false, "start with the graphical interface (windows only)")
		mode    = flag.String("mode", "", "override mode: web|tun|process|share")
		server  = flag.String("server", "", "override server name")
		level   = flag.String("log", "", "log level: debug|info|warn|error")
		subSrc  = flag.String("sub", "", "subscription URL or file, merged into config")
		listOnly = flag.Bool("list", false, "print parsed servers and exit")
		sysOn   = flag.Bool("sysproxy", false, "point the OS proxy at the local listener while running")
		logFmt  = flag.String("log-format", "text", "connection log format: text|json")
		subEvery = flag.Duration("sub-interval", 6*time.Hour, "subscription auto-refresh interval (0 disables)")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("netch-go %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return
	}

	if *useGUI {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			cfg = config.Default()
		}
		if err := gui.Run(*cfgPath, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "gui:", err)
			os.Exit(1)
		}
		return
	}

	if *listOnly {
		if err := list(*cfgPath, *subSrc); err != nil {
			fmt.Fprintln(os.Stderr, "list:", err)
			os.Exit(1)
		}
		return
	}

	if err := run(*cfgPath, *mode, *server, *level, *subSrc, *sysOn, *logFmt, *subEvery); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run(cfgPath, modeOverride, serverOverride, levelOverride, subSrc string, sysOn bool, logFmt string, subEvery time.Duration) error {
	cfg, err := config.Load(cfgPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if errors.Is(err, os.ErrNotExist) {
		cfg = config.Default()
	}

	if subSrc != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		raw, err := sub.Fetch(ctx, subSrc, 30*time.Second)
		cancel()
		if err != nil {
			return err
		}
		parsed, perr := sub.ParseList(raw)
		cfg.Servers = append(cfg.Servers, parsed...)
		if perr != nil && len(parsed) == 0 {
			return perr
		}
	}

	if modeOverride != "" {
		cfg.Mode = config.Mode(modeOverride)
	}
	if levelOverride != "" {
		cfg.Log = levelOverride
	}

	logger := logx.New(cfg.Log, os.Stderr)
	slog.SetDefault(logger)

	srv, err := cfg.Pick(serverOverride)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if subSrc != "" && subEvery > 0 {
		go sub.AutoRefresh(ctx, subSrc, subEvery, 30*time.Second, logger, func(list []config.Server) {
			logger.Info("subscription updated", "servers", len(list))
		})
	}

	if sysOn {
		ep := sysproxy.Endpoint{HTTP: cfg.Local.HTTPAddr, Socks: cfg.Local.SocksAddr}
		if err := sysproxy.Enable(ep); err != nil {
			logger.Warn("system proxy", "err", err)
		} else {
			logger.Info("system proxy set", "http", ep.HTTP, "socks", ep.Socks)
			defer func() {
				if err := sysproxy.Disable(); err != nil {
					logger.Warn("restore system proxy", "err", err)
				}
			}()
		}
	}

	logger.Info("starting",
		"mode", cfg.Mode,
		"server", srv.Name,
		"protocol", srv.Protocol,
		"socks", cfg.Local.SocksAddr,
		"http", cfg.Local.HTTPAddr,
	)

	timeout := cfg.Timeout.Std()

	upstream, err := outbound.New(srv, timeout)
	if err != nil {
		return err
	}
	defer upstream.Close()

	switch cfg.Mode {
	case config.ModeTUN:
		logger.Info("tun mode", "device", cfg.Tun.Name, "mtu", cfg.Tun.MTU)
		return tunmode.Run(ctx, tunmode.Options{
			Config:     cfg.Tun,
			Dialer:     upstream.DialContext,
			UDPTimeout: 5 * time.Minute,
		})
	case config.ModeProcess:
		logger.Info("process mode")
		return processmode.Run(ctx, processmode.Options{
			Dialer:     upstream.DialContext,
			UDPTimeout: 5 * time.Minute,
		})
	}

	// build the rule matcher; hot reload keeps it current
	var matcherPtr atomic.Pointer[rule.Matcher]
	if cfg.Rules.Enabled {
		rules := rule.Default()
		if cfg.Rules.File != "" {
			raw, rerr := os.ReadFile(cfg.Rules.File)
			if rerr != nil {
				logger.Warn("rules file", "err", rerr)
			} else if jerr := json.Unmarshal(raw, &rules); jerr != nil {
				logger.Warn("rules parse", "err", jerr)
			}
		}
		m, merr := rule.New(rules)
		if merr != nil {
			return merr
		}
		matcherPtr.Store(m)
		logger.Info("rules loaded", "count", m.Len())

		if cfg.Rules.File != "" {
			go rule.Watch(ctx, cfg.Rules.File, logger, func(nm *rule.Matcher) {
				matcherPtr.Store(nm)
			})
		}
	}

	// local DNS server resolves through the upstream
	if cfg.DNS.Enabled {
		dnsSrv := &dnsx.Server{
			Listen:   cfg.DNS.Listen,
			Upstream: []string{net.JoinHostPort(cfg.DNS.Remote, "53")},
			Dialer:   upstream.DialContext,
			Logger:   logger,
			Timeout:  5 * time.Second,
			Cache:    dnsx.NewCache(time.Duration(maxInt(cfg.DNS.CacheSec, 600)) * time.Second),
		}
		go func() {
			if err := dnsSrv.ListenAndServe(ctx); err != nil {
				logger.Warn("dns server", "err", err)
			}
		}()
		logger.Info("dns enabled", "listen", cfg.DNS.Listen, "upstream", cfg.DNS.Remote)
	}

	routeFn := func(ctx context.Context, network, addr string) (net.Conn, string, error) {
		matcher := matcherPtr.Load()
		if matcher == nil {
			c, err := upstream.DialContext(ctx, network, addr)
			return c, "proxy", err
		}
		host, port := proxy.SplitAddr(addr)
		meta := rule.Meta{Domain: host, Port: port}
		if ip, perr := netip.ParseAddr(host); perr == nil {
			meta.DestIP = ip
		}
		action, note := matcher.Match(meta)
		switch action {
		case rule.ActionReject:
			return nil, "reject", fmt.Errorf("rejected by rule %q", note)
		case rule.ActionDirect:
			c, err := (&outbound.Direct{Timeout: timeout}).DialContext(ctx, network, addr)
			return c, "direct", err
		default:
			c, err := upstream.DialContext(ctx, network, addr)
			return c, "proxy", err
		}
	}

	connSink := connlog.NewWriterSink(os.Stdout, logFmt)
	stats := &connlog.Stats{}
	bus := connlog.NewMulti(connSink, stats)
	emit := func(e connlog.Event) { bus.Emit(e) }

	errCh := make(chan error, 2)

	socks := &proxy.Socks5{
		Addr:    cfg.Local.SocksAddr,
		Logger:  logger,
		Timeout: timeout,
		Dialer:   upstream.DialContext,
		Route:    routeFn,
		OnEvent:  emit,
		MaxConns: cfg.Local.MaxConns,
	}
	httpP := &proxy.HTTP{
		Addr:    cfg.Local.HTTPAddr,
		Logger:  logger,
		Timeout: timeout,
		Route:   routeFn,
		OnEvent: emit,
	}

	go func() { errCh <- socks.ListenAndServe(ctx) }()
	go func() { errCh <- httpP.ListenAndServe(ctx) }()

	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				total, proxy_, direct, reject, fail, up, down := stats.Snapshot()
				if total == 0 {
					continue
				}
				logger.Info("stats",
					"conn", total, "proxy", proxy_, "direct", direct,
					"reject", reject, "fail", fail,
					"up_mb", up/1048576, "down_mb", down/1048576)
			}
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown")
		time.Sleep(300 * time.Millisecond)
		return nil
	case err := <-errCh:
		return err
	}
}

func list(cfgPath, subSrc string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		cfg = config.Default()
	}
	if subSrc != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		raw, ferr := sub.Fetch(ctx, subSrc, 30*time.Second)
		cancel()
		if ferr != nil {
			return ferr
		}
		parsed, perr := sub.ParseList(raw)
		cfg.Servers = append(cfg.Servers, parsed...)
		if perr != nil && len(parsed) == 0 {
			return perr
		}
	}
	if len(cfg.Servers) == 0 {
		return errors.New("no servers")
	}
	for i, s := range cfg.Servers {
		fmt.Printf("%2d  %-10s %-8s %s:%d  sni=%s\n", i+1, s.Name, s.Protocol, s.Address, s.Port, s.SNI)
	}
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
