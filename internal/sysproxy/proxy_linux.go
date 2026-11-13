//go:build linux

package sysproxy

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func Enable(ep Endpoint) error {
	server := pickServer(ep)
	if server == "" {
		return errors.New("sysproxy: empty endpoint")
	}
	if _, err := exec.LookPath("gsettings"); err != nil {
		return errors.New("sysproxy: gsettings not found (gnome only)")
	}
	host, port, ok := strings.Cut(server, ":")
	if !ok {
		return fmt.Errorf("sysproxy: bad endpoint %q", server)
	}
	sets := [][]string{
		{"set", "org.gnome.system.proxy", "mode", "manual"},
		{"set", "org.gnome.system.proxy.http", "host", host},
		{"set", "org.gnome.system.proxy.http", "port", port},
		{"set", "org.gnome.system.proxy.https", "host", host},
		{"set", "org.gnome.system.proxy.https", "port", port},
		{"set", "org.gnome.system.proxy.socks", "host", host},
		{"set", "org.gnome.system.proxy.socks", "port", port},
	}
	for _, args := range sets {
		if out, err := exec.Command("gsettings", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("sysproxy: gsettings %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func Disable() error {
	if _, err := exec.LookPath("gsettings"); err != nil {
		return nil
	}
	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
	return nil
}
