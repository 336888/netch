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

		mShow := systray.AddMenuItem("Show window", "Bring the main window to front")
		systray.AddSeparator()
		toggleItem = systray.AddMenuItem("Start", "Start or stop the proxy")
		statusItem = systray.AddMenuItem("Status: idle", "Current state")
		statusItem.Disable()
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("Quit", "Stop the proxy and exit")

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
				toggleItem.SetTitle("Stop")
				statusItem.SetTitle("Status: running")
			} else {
				toggleItem.SetTitle("Start")
				statusItem.SetTitle("Status: idle")
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
		toggleItem.SetTitle("Stop")
		statusItem.SetTitle("Status: running")
	} else {
		toggleItem.SetTitle("Start")
		statusItem.SetTitle("Status: idle")
	}
}

// Quit stops the tray loop from outside.
func Quit() {
	systray.Quit()
}
