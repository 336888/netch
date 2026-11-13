// Package sysproxy flips the OS-wide proxy setting on and off.
package sysproxy

// Endpoint is the local proxy the OS should be pointed at.
type Endpoint struct {
	HTTP  string // host:port
	Socks string // host:port
}

// Bypass is the no-proxy list shared by all platforms.
var Bypass = []string{
	"localhost", "127.*", "10.*", "172.16.*", "172.17.*", "172.18.*",
	"172.19.*", "172.2*", "172.30.*", "172.31.*", "192.168.*", "<local>",
}

func pickServer(ep Endpoint) string {
	if ep.HTTP != "" {
		return ep.HTTP
	}
	return ep.Socks
}
