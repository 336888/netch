//go:build !windows

// Package procmap resolves the process that owns a TCP connection.
// Only implemented on Windows; elsewhere it returns zero values.
package procmap

import (
	"errors"
	"net/netip"
	"runtime"
)

// PIDForConn is a no-op outside Windows.
func PIDForConn(local, remote netip.AddrPort) (uint32, error) {
	return 0, errors.New("procmap: only supported on windows, running " + runtime.GOOS)
}

// ProcessName is a no-op outside Windows.
func ProcessName(pid uint32) (string, error) {
	return "", errors.New("procmap: only supported on windows")
}
