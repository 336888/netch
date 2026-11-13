//go:build windows

// Package tray puts the app in the notification area with a right-click menu.
package tray

import (
	_ "embed"

	"github.com/energye/systray"
)

//go:embed icon.ico
var iconBytes []byte

// Hooks wires the tray menu to the application.
type Hooks struct {
	Show   func()
	Toggle func() bool
	Quit   func()
	Exit   func()
}

var (
	toggleItem *systray.MenuItem
	statusItem *systray.MenuItem
)

// Run starts the tray loop. Call it from its own goroutine.
func Run(title string, h Hooks) {
	systray.Run(func() {
		systray.SetIcon(iconBytes)
		systray.SetTitle(title)
		systray.SetTooltip(title)

		mShow := systray.AddMenuItem("显示窗口", "把主窗口调到最前")
		systray.AddSeparator()
		toggleItem = systray.AddMenuItem("启动", "启动或停止代理")
		statusItem = systray.AddMenuItem("状态：空闲", "当前状态")
		statusItem.Disable()
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("退出", "停止代理并退出程序")

		mShow.Click(func() {
			if h.Show != nil {
				h.Show()
			}
		})

		toggleItem.Click(func() {
			if h.Toggle == nil {
				return
			}
			if running := h.Toggle(); running {
				toggleItem.SetTitle("停止")
				statusItem.SetTitle("状态：运行中")
			} else {
				toggleItem.SetTitle("启动")
				statusItem.SetTitle("状态：空闲")
			}
		})

		mQuit.Click(func() {
			if h.Quit != nil {
				h.Quit()
			}
			systray.Quit()
		})
	}, func() {
		if h.Exit != nil {
			h.Exit()
		}
	})
}

// SetRunning updates tray labels when the GUI changes state directly.
func SetRunning(running bool) {
	if toggleItem == nil {
		return
	}
	if running {
		toggleItem.SetTitle("停止")
		statusItem.SetTitle("状态：运行中")
	} else {
		toggleItem.SetTitle("启动")
		statusItem.SetTitle("状态：空闲")
	}
}

// Quit stops the tray loop from outside.
func Quit() {
	systray.Quit()
}
