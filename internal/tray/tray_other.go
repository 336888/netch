//go:build !windows

// Package tray is a no-op outside Windows.
package tray

// Hooks mirrors the Windows API so callers compile everywhere.
type Hooks struct {
	Show   func()
	Toggle func() bool
	Quit   func()
	Exit   func()
}

// Run does nothing on non-Windows platforms.
func Run(title string, h Hooks) {}

// SetRunning does nothing on non-Windows platforms.
func SetRunning(running bool) {}

// Quit does nothing on non-Windows platforms.
func Quit() {}
