//go:build windows

package sysproxy

import (
	"errors"
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const regPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

var (
	wininet            = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOpt = wininet.NewProc("InternetSetOptionW")
)

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

func Enable(ep Endpoint) error {
	server := pickServer(ep)
	if server == "" {
		return errors.New("sysproxy: empty endpoint")
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, regPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("sysproxy: open key: %w", err)
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyServer", server); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyOverride", strings.Join(Bypass, ";")); err != nil {
		return err
	}
	notifyChange()
	return nil
}

func Disable() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.SET_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	_ = k.SetDWordValue("ProxyEnable", 0)
	notifyChange()
	return nil
}

func notifyChange() {
	_, _, _ = procInternetSetOpt.Call(0, internetOptionSettingsChanged, 0, 0)
	_, _, _ = procInternetSetOpt.Call(0, internetOptionRefresh, 0, 0)
}
