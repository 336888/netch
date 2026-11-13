package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

type Mode string

const (
	ModeWeb     Mode = "web"
	ModeTUN     Mode = "tun"
	ModeProcess Mode = "process"
	ModeShare   Mode = "share"
)

type Protocol string

const (
	ProtoSOCKS5 Protocol = "socks5"
	ProtoHTTP   Protocol = "http"
	ProtoSS     Protocol = "ss"
	ProtoVMess  Protocol = "vmess"
	ProtoVLESS  Protocol = "vless"
	ProtoTrojan Protocol = "trojan"
	ProtoWG     Protocol = "wireguard"
)

type Server struct {
	Name     string   `json:"name"`
	Protocol Protocol `json:"protocol"`
	Address  string   `json:"address"`
	Port     uint16   `json:"port"`

	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Method   string `json:"method,omitempty"`
	UUID     string `json:"uuid,omitempty"`
	SNI      string `json:"sni,omitempty"`
	Network  string `json:"network,omitempty"`
}

func (s Server) Endpoint() (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", s.Address, s.Port))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("server %q: %w", s.Name, err)
	}
	return ap, nil
}

type Local struct {
	SocksAddr string `json:"socks_addr"`
	HTTPAddr  string `json:"http_addr"`
	AllowLAN  bool   `json:"allow_lan"`
	MaxConns  int    `json:"max_conns,omitempty"`
}

type Tun struct {
	Name      string `json:"name"`
	MTU       int    `json:"mtu"`
	Stack     string `json:"stack"`
	AutoRoute bool   `json:"auto_route"`
}

type DNS struct {
	Remote  string   `json:"remote"`
	Local   []string `json:"local,omitempty"`
	Listen  string   `json:"listen,omitempty"`
	Enabled bool     `json:"enabled"`
	CacheSec int     `json:"cache_sec,omitempty"`
}

type Rules struct {
	File    string `json:"file,omitempty"`
	Enabled bool   `json:"enabled"`
}

type Config struct {
	Mode    Mode     `json:"mode"`
	Server  string   `json:"server"`
	Servers []Server `json:"servers"`
	Local   Local    `json:"local"`
	Tun     Tun      `json:"tun"`
	DNS     DNS      `json:"dns"`
	Rules   Rules    `json:"rules"`
	Log     string   `json:"log_level"`
	Timeout Duration `json:"timeout"`
}

type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case float64:
		*d = Duration(time.Duration(x) * time.Second)
	case string:
		p, err := time.ParseDuration(x)
		if err != nil {
			return err
		}
		*d = Duration(p)
	default:
		return errors.New("timeout: expect number(seconds) or duration string")
	}
	return nil
}

func (d Duration) Std() time.Duration {
	if d == 0 {
		return 30 * time.Second
	}
	return time.Duration(d)
}

func Default() Config {
	return Config{
		Mode: ModeWeb,
		Local: Local{
			SocksAddr: "127.0.0.1:1080",
			HTTPAddr:  "127.0.0.1:1081",
		},
		Tun: Tun{
			Name:      "Netch",
			MTU:       1500,
			Stack:     "gvisor",
			AutoRoute: true,
		},
		DNS: DNS{Remote: "1.1.1.1", Listen: "127.0.0.1:53"},
		Log: "info",
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	var errs []error
	if c.Mode == "" {
		errs = append(errs, errors.New("mode is required"))
	}
	if len(c.Servers) == 0 {
		errs = append(errs, errors.New("no servers configured"))
	}
	for i, s := range c.Servers {
		if s.Name == "" {
			errs = append(errs, fmt.Errorf("servers[%d]: name is required", i))
		}
		if s.Protocol == "direct" {
			continue
		}
		if _, err := s.Endpoint(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c Config) Pick(name string) (Server, error) {
	if len(c.Servers) == 0 {
		return Server{}, errors.New("no servers configured")
	}
	if name == "" {
		return c.Servers[0], nil
	}
	for _, s := range c.Servers {
		if s.Name == name {
			return s, nil
		}
	}
	return Server{}, fmt.Errorf("server %q not found", name)
}
