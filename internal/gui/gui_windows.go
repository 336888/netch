//go:build windows

package gui

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"github.com/netchx/netch-go/internal/config"
	"github.com/netchx/netch-go/internal/connlog"
	"github.com/netchx/netch-go/internal/logx"
	"github.com/netchx/netch-go/internal/outbound"
	"github.com/netchx/netch-go/internal/proxy"
	"github.com/netchx/netch-go/internal/sysproxy"
	"github.com/netchx/netch-go/internal/tray"
)

var modes = []string{"web", "tun", "process", "share"}

type serverModel struct {
	walk.TableModelBase
	items   []config.Server
	latency map[string]string
}

func (m *serverModel) RowCount() int { return len(m.items) }

func (m *serverModel) Value(row, col int) any {
	if row < 0 || row >= len(m.items) {
		return ""
	}
	s := m.items[row]
	switch col {
	case 0:
		return s.Name
	case 1:
		return string(s.Protocol)
	case 2:
		return s.Address
	case 3:
		return s.Port
	case 4:
		return s.SNI
	case 5:
		if m.latency != nil {
			if v, ok := m.latency[s.Name]; ok {
				return v
			}
		}
		return "-"
	}
	return ""
}

func (m *serverModel) Reset(items []config.Server) {
	m.items = items
	m.latency = make(map[string]string, len(items))
	m.PublishRowsReset()
}

func (m *serverModel) setLatency(name, v string) {
	if m.latency == nil {
		m.latency = make(map[string]string)
	}
	m.latency[name] = v
	m.PublishRowChanged(m.index(name))
}

func (m *serverModel) index(name string) int {
	for i, s := range m.items {
		if s.Name == name {
			return i
		}
	}
	return 0
}

type App struct {
	cfgPath string
	cfg     config.Config

	mw       *walk.MainWindow
	modeBox  *walk.ComboBox
	btn      *walk.PushButton
	status   *walk.Label
	logs     *walk.TextEdit
	table    *walk.TableView
	model    *serverModel
	sysProxy *walk.CheckBox

	sink     *connlog.ChanSink
	ring     *connlog.Ring
	stats    *connlog.Stats
	connTable *walk.TableView
	connModel *connModel
	lastGen   uint64
	pending  strings.Builder
	pmu      sync.Mutex
	paused   bool
	pauseBtn *walk.PushButton
	clearBtn *walk.PushButton
	pingBtn  *walk.PushButton

	mu       sync.Mutex
	cancel   context.CancelFunc
	quitting bool
}

func Run(cfgPath string, cfg config.Config) error {
	a := &App{cfgPath: cfgPath, cfg: cfg, model: &serverModel{}}
	a.sink = connlog.NewChanSink(4096)
	a.ring = connlog.NewRing(500)
	a.stats = &connlog.Stats{}
	a.connModel = &connModel{}

	if err := (MainWindow{
		AssignTo: &a.mw,
		Title:    "Netch",
		MinSize:  Size{Width: 760, Height: 560},
		Size:     Size{Width: 880, Height: 640},
		Layout:   VBox{},
		Children: []Widget{
			Composite{
				Layout: HBox{},
				Children: []Widget{
					Label{Text: "Mode:"},
					ComboBox{
						AssignTo:     &a.modeBox,
						Model:        modes,
						CurrentIndex: idxOf(modes, string(cfg.Mode)),
					},
					CheckBox{
						AssignTo: &a.sysProxy,
						Text:     "Set system proxy",
					},
					HSpacer{},
					PushButton{
						AssignTo:  &a.pingBtn,
						Text:      "Test latency",
						OnClicked: func() { a.testLatency() },
					},
					PushButton{
						Text:      "Settings",
						OnClicked: func() { a.openSettings() },
					},
					PushButton{
						AssignTo:  &a.pauseBtn,
						Text:      "Pause log",
						OnClicked: func() { a.togglePause() },
					},
					PushButton{
						AssignTo:  &a.clearBtn,
						Text:      "Clear",
						OnClicked: func() { a.clearLogs() },
					},
					PushButton{
						AssignTo:  &a.btn,
						Text:      "Start",
						OnClicked: func() { a.toggle() },
					},
				},
			},
			TableView{
				AssignTo:              &a.table,
				Model:                 a.model,
				AlternatingRowBG:      true,
				ColumnsOrderable:      true,
				Columns: []TableViewColumn{
					{Title: "Name", Width: 180},
					{Title: "Protocol", Width: 100},
					{Title: "Address", Width: 200},
					{Title: "Port", Width: 80},
					{Title: "SNI", Width: 140},
					{Title: "Latency", Width: 80},
				},
				OnCurrentIndexChanged: func() {},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					Label{Text: "Status:"},
					Label{AssignTo: &a.status, Text: "idle"},
				},
			},
			TabWidget{
				Pages: []TabPage{
					{
						Title:  "Log",
						Layout: VBox{},
						Children: []Widget{
							TextEdit{AssignTo: &a.logs, ReadOnly: true, VScroll: true},
						},
					},
					{
						Title:  "Connections",
						Layout: VBox{},
						Children: []Widget{
							TableView{
								AssignTo:         &a.connTable,
								Model:            a.connModel,
								AlternatingRowBG: true,
								Columns: []TableViewColumn{
									{Title: "Time", Width: 90},
									{Title: "Proto", Width: 60},
									{Title: "Action", Width: 60},
									{Title: "Target", Width: 260},
									{Title: "ms", Width: 60},
									{Title: "Up", Width: 80},
									{Title: "Down", Width: 80},
								},
							},
						},
					},
				},
			},
		},
	}).Create(); err != nil {
		return err
	}

	a.model.Reset(cfg.Servers)
	go a.pumpLogs()

	go tray.Run("Netch", tray.Hooks{
		Show: func() {
			a.mw.Synchronize(func() {
				a.mw.Show()
				a.mw.Activate()
			})
		},
		Toggle: func() bool {
			a.mu.Lock()
			running := a.cancel != nil
			a.mu.Unlock()
			if running {
				a.stop()
				return false
			}
			a.start()
			return true
		},
		Quit: func() {
			a.quitting = true
			a.stop()
			a.mw.Synchronize(func() { a.mw.Close() })
		},
		Exit: func() {},
	})

	a.mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if !a.quitting {
			*canceled = true
			a.mw.Hide()
			return
		}
		a.stop()
		tray.Quit()
	})
	a.mw.Run()
	return nil
}

func idxOf(list []string, v string) int {
	for i, s := range list {
		if s == v {
			return i
		}
	}
	return 0
}

func (a *App) appendLog(s string) {
	if a.logs == nil {
		return
	}
	a.mw.Synchronize(func() {
		cur := a.logs.Text()
		a.logs.SetText(cur + s + "\r\n")
	})
}

func (a *App) setStatus(s string) {
	if a.status == nil {
		return
	}
	a.mw.Synchronize(func() { a.status.SetText(s) })
}

func (a *App) toggle() {
	a.mu.Lock()
	running := a.cancel != nil
	a.mu.Unlock()
	if running {
		a.stop()
	} else {
		a.start()
	}
}

func (a *App) selected() (config.Server, error) {
	idx := 0
	if a.table != nil {
		idx = a.table.CurrentIndex()
	}
	if idx < 0 || idx >= len(a.cfg.Servers) {
		return config.Server{}, fmt.Errorf("no server selected")
	}
	return a.cfg.Servers[idx], nil
}

func (a *App) start() {
	srv, err := a.selected()
	if err != nil {
		a.appendLog("select: " + err.Error())
		return
	}
	mode := a.cfg.Mode
	if a.modeBox != nil && a.modeBox.CurrentIndex() >= 0 {
		mode = config.Mode(modes[a.modeBox.CurrentIndex()])
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.mu.Lock()
	a.cancel = cancel
	a.mu.Unlock()

	a.btn.SetText("Stop")
	tray.SetRunning(true)
	a.setStatus(fmt.Sprintf("running %s via %s", mode, srv.Name))
	a.appendLog(fmt.Sprintf("start mode=%s server=%s proto=%s", mode, srv.Name, srv.Protocol))

	if a.sysProxy != nil && a.sysProxy.Checked() {
		ep := sysproxy.Endpoint{HTTP: a.cfg.Local.HTTPAddr, Socks: a.cfg.Local.SocksAddr}
		if err := sysproxy.Enable(ep); err != nil {
			a.appendLog("sysproxy: " + err.Error())
		} else {
			a.appendLog("system proxy set: " + ep.HTTP)
		}
	}

	go func() {
		timeout := a.cfg.Timeout.Std()
		up, err := outbound.New(srv, timeout)
		if err != nil {
			a.appendLog("outbound: " + err.Error())
			a.finish()
			return
		}
		defer up.Close()

		logger := logx.New("debug", writerFunc(func(p []byte) (int, error) {
			a.appendLog(string(p))
			return len(p), nil
		}))

		bus := connlog.NewMulti(a.sink, a.stats, a.ring)
		emit := func(e connlog.Event) { bus.Emit(e) }

		socks := &proxy.Socks5{
			Addr:     a.cfg.Local.SocksAddr,
			Logger:   logger,
			Timeout:  timeout,
			Dialer:   up.DialContext,
			Route:    proxy.DirectRoute(up.DialContext),
			OnEvent:  emit,
			MaxConns: a.cfg.Local.MaxConns,
		}
		httpP := &proxy.HTTP{
			Addr:    a.cfg.Local.HTTPAddr,
			Logger:  logger,
			Timeout: timeout,
			Route:   proxy.DirectRoute(up.DialContext),
			OnEvent: emit,
		}

		errCh := make(chan error, 2)
		go func() { errCh <- socks.ListenAndServe(ctx) }()
		go func() { errCh <- httpP.ListenAndServe(ctx) }()

		select {
		case <-ctx.Done():
		case err := <-errCh:
			if err != nil {
				a.appendLog("proxy: " + err.Error())
			}
		}
		a.finish()
	}()
}

func (a *App) stop() {
	a.mu.Lock()
	c := a.cancel
	a.cancel = nil
	a.mu.Unlock()
	if c != nil {
		c()
		a.appendLog("stop requested")
	}
	if a.sysProxy != nil && a.sysProxy.Checked() {
		_ = sysproxy.Disable()
		a.appendLog("system proxy cleared")
	}
	tray.SetRunning(false)
}

func (a *App) finish() {
	a.mw.Synchronize(func() {
		a.btn.SetText("Start")
		a.status.SetText("idle")
	})
	a.mu.Lock()
	a.cancel = nil
	a.mu.Unlock()
}

func (a *App) testLatency() {
	if a.pingBtn != nil {
		a.pingBtn.SetEnabled(false)
		defer a.pingBtn.SetEnabled(true)
	}
	a.appendLog("latency test: " + fmt.Sprint(len(a.cfg.Servers)) + " servers")

	for _, srv := range a.cfg.Servers {
		srv := srv
		go func() {
			if srv.Protocol == "direct" {
				a.mw.Synchronize(func() { a.model.setLatency(srv.Name, "local") })
				return
			}
			addr := net.JoinHostPort(srv.Address, fmt.Sprint(srv.Port))
			start := time.Now()
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				a.mw.Synchronize(func() { a.model.setLatency(srv.Name, "fail") })
				return
			}
			_ = conn.Close()
			ms := time.Since(start).Milliseconds()
			a.mw.Synchronize(func() { a.model.setLatency(srv.Name, fmt.Sprintf("%d ms", ms)) })
		}()
	}
}

func (a *App) pumpLogs() {
	t := time.NewTicker(120 * time.Millisecond)
	connTick := time.NewTicker(700 * time.Millisecond)
	defer t.Stop()
	defer connTick.Stop()
	for {
		select {
		case line := <-a.sink.C():
			a.pmu.Lock()
			a.pending.WriteString(line)
			a.pending.WriteString("\r\n")
			a.pmu.Unlock()
		case <-t.C:
			a.flushLogs()
		case <-connTick.C:
			a.refreshConns()
		}
	}
}

func (a *App) refreshConns() {
	if a.connTable == nil || a.ring == nil {
		return
	}
	gen := a.ring.Generation()
	if gen == a.lastGen {
		return
	}
	a.lastGen = gen

	events := a.ring.Snapshot()
	if len(events) > 300 {
		events = events[len(events)-300:]
	}
	a.mw.Synchronize(func() {
		a.connModel.Reset(events)
	})
}

func (a *App) flushLogs() {
	a.pmu.Lock()
	if a.paused || a.pending.Len() == 0 {
		a.pending.Reset()
		a.pmu.Unlock()
		return
	}
	batch := a.pending.String()
	a.pending.Reset()
	a.pmu.Unlock()

	a.mw.Synchronize(func() {
		cur := a.logs.Text()
		next := cur + batch
		if lines := strings.Count(next, "\n"); lines > 2000 {
			if idx := strings.Index(next, "\n"); idx >= 0 {
				next = next[idx+1:]
			}
		}
		a.logs.SetText(next)
		a.logs.SetFocus()
	})
}

func (a *App) togglePause() {
	a.pmu.Lock()
	a.paused = !a.paused
	paused := a.paused
	a.pmu.Unlock()
	if paused {
		a.pauseBtn.SetText("Resume log")
	} else {
		a.pauseBtn.SetText("Pause log")
	}
}

func (a *App) clearLogs() {
	a.pmu.Lock()
	a.pending.Reset()
	a.pmu.Unlock()
	if a.logs != nil {
		a.logs.SetText("")
	}
}

type connModel struct {
	walk.TableModelBase
	items []connlog.Event
}

func (m *connModel) RowCount() int { return len(m.items) }

func (m *connModel) Value(row, col int) any {
	if row < 0 || row >= len(m.items) {
		return ""
	}
	e := m.items[row]
	switch col {
	case 0:
		return e.Time.Format("15:04:05")
	case 1:
		return e.Proto
	case 2:
		return e.Action
	case 3:
		return e.Target
	case 4:
		return e.DurMs
	case 5:
		return e.Up
	case 6:
		return e.Down
	}
	return ""
}

func (m *connModel) Reset(items []connlog.Event) {
	m.items = items
	m.PublishRowsReset()
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
