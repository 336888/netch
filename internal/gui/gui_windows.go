//go:build windows

package gui

import (
	"context"
	"fmt"
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
)

var modes = []string{"web", "tun", "process", "share"}

type serverModel struct {
	walk.TableModelBase
	items []config.Server
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
	}
	return ""
}

func (m *serverModel) Reset(items []config.Server) {
	m.items = items
	m.PublishRowsReset()
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
	stats    *connlog.Stats
	pending  strings.Builder
	pmu      sync.Mutex
	paused   bool
	pauseBtn *walk.PushButton
	clearBtn *walk.PushButton

	mu     sync.Mutex
	cancel context.CancelFunc
}

func Run(cfgPath string, cfg config.Config) error {
	a := &App{cfgPath: cfgPath, cfg: cfg, model: &serverModel{}}
	a.sink = connlog.NewChanSink(4096)
	a.stats = &connlog.Stats{}

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
					{Title: "SNI", Width: 180},
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
			TextEdit{AssignTo: &a.logs, ReadOnly: true, VScroll: true},
		},
	}).Create(); err != nil {
		return err
	}

	a.model.Reset(cfg.Servers)
	go a.pumpLogs()

	a.mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		a.stop()
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

		bus := connlog.NewMulti(a.sink, a.stats)
		emit := func(e connlog.Event) { bus.Emit(e) }

		socks := &proxy.Socks5{Addr: a.cfg.Local.SocksAddr, Logger: logger, Timeout: timeout, Dialer: up.DialContext, OnEvent: emit}
		httpP := &proxy.HTTP{Addr: a.cfg.Local.HTTPAddr, Logger: logger, Timeout: timeout, Dialer: up.DialContext, OnEvent: emit}

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

func (a *App) pumpLogs() {
	t := time.NewTicker(120 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case line := <-a.sink.C():
			a.pmu.Lock()
			a.pending.WriteString(line)
			a.pending.WriteString("\r\n")
			a.pmu.Unlock()
		case <-t.C:
			a.flushLogs()
		}
	}
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

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
