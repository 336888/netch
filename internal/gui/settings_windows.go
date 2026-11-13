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
		Title:    "设置",
		MinSize:  Size{Width: 460, Height: 380},
		Layout:   VBox{},
		Children: []Widget{
			GroupBox{
				Title:  "本地监听",
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "SOCKS5 地址："},
					LineEdit{AssignTo: &socksEdit, Text: a.cfg.Local.SocksAddr},
					Label{Text: "HTTP 地址："},
					LineEdit{AssignTo: &httpEdit, Text: a.cfg.Local.HTTPAddr},
					Label{Text: "允许局域网："},
					CheckBox{AssignTo: &lanCheck, Checked: a.cfg.Local.AllowLAN},
				},
			},
			GroupBox{
				Title:  "DNS",
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "启用本地 DNS："},
					CheckBox{AssignTo: &dnsCheck, Checked: a.cfg.DNS.Enabled},
					Label{Text: "监听地址："},
					LineEdit{AssignTo: &dnsEdit, Text: a.cfg.DNS.Listen},
					Label{Text: "上游服务器："},
					LineEdit{AssignTo: &remoteEdit, Text: a.cfg.DNS.Remote},
				},
			},
			GroupBox{
				Title:  "运行时",
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "启用分流规则："},
					CheckBox{AssignTo: &rulesCheck, Checked: a.cfg.Rules.Enabled},
					Label{Text: "日志级别："},
					ComboBox{AssignTo: &levelCombo, Model: levels, CurrentIndex: idxOf(levels, a.cfg.Log)},
					Label{Text: "超时（秒）："},
					NumberEdit{AssignTo: &timeoutEdit, Value: float64(int(a.cfg.Timeout.Std().Seconds()))},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						Text: "取消",
						OnClicked: func() {
							dlg.Cancel()
						},
					},
					PushButton{
						Text: "保存",
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
		a.appendLog("序列化配置失败：" + err.Error())
		return
	}
	if err := os.WriteFile(a.cfgPath, raw, 0o644); err != nil {
		a.appendLog("写入配置失败：" + err.Error())
		return
	}
	a.appendLog(fmt.Sprintf("配置已保存，重启生效（超时 %d 秒）", timeoutSec))
}

func timeDur(sec int) int64 {
	if sec <= 0 {
		sec = 30
	}
	n, _ := strconv.Atoi(strconv.Itoa(sec))
	return int64(n) * 1e9
}
