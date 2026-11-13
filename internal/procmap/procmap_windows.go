//go:build windows

// Package procmap resolves the process that owns a TCP connection on Windows.
// It backs per-process routing in TUN mode without a kernel driver.
package procmap

import (
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tcpTableOwnerPidAll = 5
	afInet              = 2
	afInet6             = 23
)

// MIB_TCPROW_OWNER_PID mirrors the layout used by GetExtendedTcpTable.
type tcpRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type tcp6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

var (
	iphlpapi               = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

// PIDForConn returns the process ID that owns the given 4-tuple. Returns 0 when
// the connection is not found, which callers should treat as "unknown".
func PIDForConn(local, remote netip.AddrPort) (uint32, error) {
	if local.Addr().Is4() && remote.Addr().Is4() {
		return pidV4(local, remote)
	}
	if local.Addr().Is6() || remote.Addr().Is6() {
		return pidV6(local, remote)
	}
	return 0, errors.New("procmap: mixed address families")
}

func pidV4(local, remote netip.AddrPort) (uint32, error) {
	buf, err := tcpTable(afInet)
	if err != nil {
		return 0, err
	}
	const rowSize = int(unsafe.Sizeof(tcpRowOwnerPID{}))
	count := len(buf) / rowSize
	if count == 0 {
		return 0, nil
	}

	la := local.Addr().As4()
	ra := remote.Addr().As4()
	lport := htons(local.Port())
	rport := htons(remote.Port())

	rows := unsafe.Slice((*tcpRowOwnerPID)(unsafe.Pointer(&buf[0])), count)
	for i := range rows {
		r := rows[i]
		if r.LocalAddr == le32(la) && r.LocalPort == uint32(lport) &&
			r.RemoteAddr == le32(ra) && r.RemotePort == uint32(rport) {
			return r.OwningPID, nil
		}
	}
	return 0, nil
}

func pidV6(local, remote netip.AddrPort) (uint32, error) {
	buf, err := tcpTable(afInet6)
	if err != nil {
		return 0, err
	}
	const rowSize = int(unsafe.Sizeof(tcp6RowOwnerPID{}))
	count := len(buf) / rowSize
	if count == 0 {
		return 0, nil
	}

	la := local.Addr().As16()
	ra := remote.Addr().As16()
	lport := htons(local.Port())
	rport := htons(remote.Port())

	rows := unsafe.Slice((*tcp6RowOwnerPID)(unsafe.Pointer(&buf[0])), count)
	for i := range rows {
		r := rows[i]
		if r.LocalAddr == la && r.LocalPort == uint32(lport) &&
			r.RemoteAddr == ra && r.RemotePort == uint32(rport) {
			return r.OwningPID, nil
		}
	}
	return 0, nil
}

func tcpTable(family uint32) ([]byte, error) {
	var size uint32
	ret, _, _ := procGetExtendedTcpTable.Call(
		0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family),
		tcpTableOwnerPidAll, 0)
	if ret != 0 && ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("procmap: size query failed with %d", ret)
	}
	if size == 0 {
		return nil, nil
	}

	buf := make([]byte, size)
	ret, _, _ = procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
		0, uintptr(family), tcpTableOwnerPidAll, 0)
	if ret != 0 {
		return nil, fmt.Errorf("procmap: table query failed with %d", ret)
	}
	// First 4 bytes are the row count; the rows follow.
	if len(buf) < 4 {
		return nil, nil
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	offset := uintptr(4)
	rowSize := uintptr(unsafe.Sizeof(tcpRowOwnerPID{}))
	if family == afInet6 {
		rowSize = uintptr(unsafe.Sizeof(tcp6RowOwnerPID{}))
	}
	end := offset + uintptr(n)*rowSize
	if end > uintptr(len(buf)) {
		end = uintptr(len(buf))
	}
	return buf[offset:end], nil
}

// htons converts a port to network byte order.
func htons(p uint16) uint16 {
	return p<<8 | p>>8
}

// le32 reads four bytes as a little-endian uint32, matching MIB_TCPROW layout.
func le32(b [4]byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// ProcessName returns the executable name for a PID.
func ProcessName(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	full := windows.UTF16ToString(buf[:size])
	for i := len(full) - 1; i >= 0; i-- {
		if full[i] == '\\' || full[i] == '/' {
			return full[i+1:], nil
		}
	}
	return full, nil
}
