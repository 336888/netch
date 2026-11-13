//go:build windows

package gui

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"github.com/netchx/netch-go/internal/config"
)

// openSettings shows a modal editor for the fields people actually change.
func (a *App) openSettings() {
	var (
		dlg       *walk.Dialog
		socksEdit *walk.LineEdit
		httpEdit  *walk.LineEdit
		dnsEdit   *walk.LineEdit
		remoteEdit *walk.LineEdit
		timeoutEdit *walk.NumberEdit
		levelCombo *walk.ComboBox
		dnsCheck  *walk.CheckBox
		rulesCheck *walk.CheckBox
		lanCheck  *walk.CheckBox
	)

	levels := []string{"debug", "info", "warn", "error"}

	err := Dialog{
		AssignTo: &dlg,
		Title:    "Settings",
		MinSize:  Size{Width: 460, Height: 380},
		Layout:   VBox{},
		Children: []Widget{
			GroupBox{
				Title:  "Local listeners",
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "SOCKS5 address:"},
					LineEdit{AssignTo: &socksEdit, Text: a.cfg.Local.SocksAddr},
					Label{Text: "HTTP address:"},
					LineEdit{AssignTo: &httpEdit, Text: a.cfg.Local.HTTPAddr},
					Label{Text: "Allow LAN:"},
					CheckBox{AssignTo: &lanCheck, Checked: a.cfg.Local.AllowLAN},
				},
			},
			GroupBox{
				Title:  "DNS",
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "Enable local DNS:"},
					CheckBox{AssignTo: &dnsCheck, Checked: a.cfg.DNS.Enabled},
					Label{Text: "Listen address:"},
					LineEdit{AssignTo: &dnsEdit, Text: a.cfg.DNS.Listen},
					Label{Text: "Upstream:"},
					LineEdit{AssignTo: &remoteEdit, Text: a.cfg.DNS.Remote},
				},
			},
			GroupBox{
				Title:  "Runtime",
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "Rules enabled:"},
					CheckBox{AssignTo: &rulesCheck, Checked: a.cfg.Rules.Enabled},
					Label{Text: "Log level:"},
					ComboBox{AssignTo: &levelCombo, Model: levels, CurrentIndex: idxOf(levels, a.cfg.Log)},
					Label{Text: "Timeout (sec):"},
					NumberEdit{AssignTo: &timeoutEdit, Value: float64(int(a.cfg.Timeout.Std().Seconds()))},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						Text: "Cancel",
						OnClicked: func() {
							dlg.Cancel()
						},
					},
					PushButton{
						Text: "Save",
						OnClicked: func() {
							a.applySettings(socksEdit.Text(), httpEdit.Text(),
								dnsCheck.Checked(), dnsEdit.Text(), remoteEdit.Text(),
								rulesCheck.Checked(), lanCheck.Checked(),
								levels[levelCombo.CurrentIndex()],
								int(timeoutEdit.Value()))
							dlg.Accept()
						},
					},
				},
			},
		},
	}.Create(a.mw)
	if err != nil {
		a.appendLog("settings: " + err.Error())
		return
	}
	dlg.Run()
}

func (a *App) applySettings(socks, http string, dnsOn bool, dnsAddr, dnsRemote string,
	rulesOn, lan bool, level string, timeoutSec int) {

	a.cfg.Local.SocksAddr = socks
	a.cfg.Local.HTTPAddr = http
	a.cfg.Local.AllowLAN = lan
	a.cfg.DNS.Enabled = dnsOn
	if dnsAddr != "" {
		a.cfg.DNS.Listen = dnsAddr
	}
	if dnsRemote != "" {
		a.cfg.DNS.Remote = dnsRemote
	}
	a.cfg.Rules.Enabled = rulesOn
	a.cfg.Log = level
	a.cfg.Timeout = config.Duration(timeDur(timeoutSec))

	raw, err := json.MarshalIndent(a.cfg, "", "  ")
	if err != nil {
		a.appendLog("settings marshal: " + err.Error())
		return
	}
	if err := os.WriteFile(a.cfgPath, raw, 0o644); err != nil {
		a.appendLog("settings write: " + err.Error())
		return
	}
	a.appendLog(fmt.Sprintf("settings saved, restart to apply (timeout=%ds)", timeoutSec))
}

func timeDur(sec int) int64 {
	if sec <= 0 {
		sec = 30
	}
	n, _ := strconv.Atoi(strconv.Itoa(sec))
	return int64(n) * 1e9
}
