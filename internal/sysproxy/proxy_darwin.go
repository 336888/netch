//go:build darwin

package sysproxy

import (
	"errors"
	"os/exec"
	"strings"
)

func services() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	var list []string
	for _, line := range strings.Split(string(out), "\n")[1:] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		list = append(list, line)
	}
	return list
}

func Enable(ep Endpoint) error {
	if ep.HTTP == "" && ep.Socks == "" {
		return errors.New("sysproxy: empty endpoint")
	}
	for _, svc := range services() {
		if ep.HTTP != "" {
			host, port, _ := strings.Cut(ep.HTTP, ":")
			_ = exec.Command("networksetup", "-setwebproxy", svc, host, port).Run()
			_ = exec.Command("networksetup", "-setsecurewebproxy", svc, host, port).Run()
		}
		if ep.Socks != "" {
			host, port, _ := strings.Cut(ep.Socks, ":")
			_ = exec.Command("networksetup", "-setsocksfirewallproxy", svc, host, port).Run()
		}
	}
	return nil
}

func Disable() error {
	for _, svc := range services() {
		_ = exec.Command("networksetup", "-setwebproxystate", svc, "off").Run()
		_ = exec.Command("networksetup", "-setsecurewebproxystate", svc, "off").Run()
		_ = exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "off").Run()
	}
	return nil
}
