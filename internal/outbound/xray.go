package outbound

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/netchx/netch-go/internal/config"
)

// xrayBackend shells out to Xray for REALITY nodes that sing-box cannot
// authenticate against. Xray and sing-box differ in how they build the
// ClientHello, so a node provisioned for one may reject the other.
type xrayBackend struct {
	cmd     *exec.Cmd
	socks   string
	timeout time.Duration
	cfgFile string
}

// Available reports whether an xray binary sits next to the executable.
func Available() (string, bool) {
	candidates := []string{"xray", "xray.exe"}
	exe, err := os.Executable()
	var dirs []string
	if err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	dirs = append(dirs, ".")
	for _, d := range dirs {
		for _, name := range candidates {
			p := filepath.Join(d, name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p, true
			}
		}
	}
	if p, err := exec.LookPath("xray"); err == nil {
		return p, true
	}
	return "", false
}

func newXrayBackend(s config.Server, timeout time.Duration) (Dialer, error) {
	bin, ok := Available()
	if !ok {
		return nil, fmt.Errorf("xray: binary not found (place xray next to the executable)")
	}

	port, err := freePort()
	if err != nil {
		return nil, fmt.Errorf("xray: %w", err)
	}
	socks := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	cfg := buildXrayConfig(s, port)
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp("", "netch-xray-*.json")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	f.Close()

	cmd := exec.Command(bin, "run", "-c", path)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("xray: start: %w", err)
	}

	b := &xrayBackend{cmd: cmd, socks: socks, timeout: timeout, cfgFile: path}

	// wait for the socks listener to come up
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.DialTimeout("tcp", socks, 300*time.Millisecond)
		if derr == nil {
			c.Close()
			return b, nil
		}
		time.Sleep(120 * time.Millisecond)
	}
	b.Close()
	return nil, fmt.Errorf("xray: socks listener did not come up on %s", socks)
}

func (b *xrayBackend) Close() error {
	if b.cmd != nil && b.cmd.Process != nil {
		_ = b.cmd.Process.Kill()
		_, _ = b.cmd.Process.Wait()
	}
	if b.cfgFile != "" {
		_ = os.Remove(b.cfgFile)
	}
	return nil
}

func (b *xrayBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	up := &socks5Upstream{server: b.socks, timeout: b.timeout}
	return up.DialContext(ctx, network, addr)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func buildXrayConfig(s config.Server, socksPort int) map[string]any {
	user := map[string]any{
		"id":         s.UUID,
		"encryption": "none",
	}
	if s.Flow != "" {
		user["flow"] = s.Flow
	}
	return map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			map[string]any{
				"port":     socksPort,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]any{"udp": true},
			},
		},
		"outbounds": []any{
			map[string]any{
				"protocol": "vless",
				"settings": map[string]any{
					"vnext": []any{
						map[string]any{
							"address": s.Address,
							"port":    s.Port,
							"users":   []any{user},
						},
					},
				},
				"streamSettings": map[string]any{
					"network":  "tcp",
					"security": "reality",
					"realitySettings": map[string]any{
						"serverName":  s.SNI,
						"fingerprint": s.Fingerprint,
						"publicKey":   s.PublicKey,
						"shortId":     s.ShortID,
					},
				},
			},
		},
	}
}
