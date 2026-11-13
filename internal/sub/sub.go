// Package sub parses share links and subscription payloads into config.Server.
package sub

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/netchx/netch-go/internal/config"
)

// Parse decodes a single share link.
func Parse(uri string) (config.Server, error) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return config.Server{}, errors.New("sub: empty line")
	}
	scheme, rest, ok := strings.Cut(uri, "://")
	if !ok {
		return config.Server{}, fmt.Errorf("sub: missing scheme in %q", truncate(uri))
	}
	switch strings.ToLower(scheme) {
	case "ss":
		return parseSS(rest)
	case "vmess":
		return parseVMess(rest)
	case "vless":
		return parseVLESS(rest)
	case "trojan":
		return parseTrojan(rest)
	case "socks5", "socks":
		return parseSOCKS5(rest)
	case "http":
		return parseHTTP(rest)
	default:
		return config.Server{}, fmt.Errorf("sub: unsupported scheme %q", scheme)
	}
}

// ParseList decodes a subscription payload. Plain newline lists and
// base64-wrapped lists are both accepted.
func ParseList(payload []byte) ([]config.Server, error) {
	text := strings.TrimSpace(string(payload))
	if !strings.Contains(text, "://") {
		if dec, err := decodeBase64(text); err == nil {
			text = strings.TrimSpace(string(dec))
		}
	}
	var out []config.Server
	var errs []error
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s, err := Parse(line)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", i+1, err))
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errors.Join(append([]error{errors.New("sub: no servers parsed")}, errs...)...)
	}
	return out, errors.Join(errs...)
}

func parseSS(rest string) (config.Server, error) {
	name := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		name, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")

	var methodPass, hostPort string
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		mp := rest[:at]
		if dec, err := decodeBase64(mp); err == nil {
			mp = string(dec)
		}
		methodPass, hostPort = mp, rest[at+1:]
	} else {
		dec, err := decodeBase64(rest)
		if err != nil {
			return config.Server{}, fmt.Errorf("ss: %w", err)
		}
		s := string(dec)
		at := strings.LastIndexByte(s, '@')
		if at < 0 {
			return config.Server{}, errors.New("ss: missing @ in payload")
		}
		methodPass, hostPort = s[:at], s[at+1:]
	}

	method, password, ok := strings.Cut(methodPass, ":")
	if !ok {
		return config.Server{}, errors.New("ss: method:password expected")
	}
	host, port, err := splitHostPort(hostPort)
	if err != nil {
		return config.Server{}, err
	}
	if name == "" {
		name = host
	}
	return config.Server{
		Name:     name,
		Protocol: config.ProtoSS,
		Address:  host,
		Port:     port,
		Method:   method,
		Password: password,
	}, nil
}

type vmessJSON struct {
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port any    `json:"port"`
	ID   string `json:"id"`
	Aid  any    `json:"aid"`
	Net  string `json:"net"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
}

func parseVMess(rest string) (config.Server, error) {
	dec, err := decodeBase64(rest)
	if err != nil {
		return config.Server{}, fmt.Errorf("vmess: %w", err)
	}
	var v vmessJSON
	if err := json.Unmarshal(dec, &v); err != nil {
		return config.Server{}, fmt.Errorf("vmess: json: %w", err)
	}
	port, err := toPort(v.Port)
	if err != nil {
		return config.Server{}, fmt.Errorf("vmess: %w", err)
	}
	sni := v.SNI
	if sni == "" {
		sni = v.Host
	}
	name := v.PS
	if name == "" {
		name = v.Add
	}
	return config.Server{
		Name:     name,
		Protocol: config.ProtoVMess,
		Address:  v.Add,
		Port:     port,
		UUID:     v.ID,
		SNI:      sni,
		Network:  v.Net,
	}, nil
}

func parseVLESS(rest string) (config.Server, error) {
	u, err := url.Parse("vless://" + rest)
	if err != nil {
		return config.Server{}, fmt.Errorf("vless: %w", err)
	}
	port, err := toPort(u.Port())
	if err != nil {
		return config.Server{}, err
	}
	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("host")
	}
	name := u.Fragment
	if name == "" {
		name = u.Hostname()
	}
	return config.Server{
		Name:        name,
		Protocol:    config.ProtoVLESS,
		Address:     u.Hostname(),
		Port:        port,
		UUID:        u.User.Username(),
		SNI:         sni,
		Network:     firstNonEmpty(q.Get("type"), "tcp"),
		Security:    q.Get("security"),
		PublicKey:   q.Get("pbk"),
		ShortID:     q.Get("sid"),
		Fingerprint: firstNonEmpty(q.Get("fp"), "chrome"),
		Flow:        q.Get("flow"),
	}, nil
}

func parseTrojan(rest string) (config.Server, error) {
	u, err := url.Parse("trojan://" + rest)
	if err != nil {
		return config.Server{}, fmt.Errorf("trojan: %w", err)
	}
	port, err := toPort(u.Port())
	if err != nil {
		return config.Server{}, err
	}
	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	if sni == "" {
		sni = u.Hostname()
	}
	name := u.Fragment
	if name == "" {
		name = u.Hostname()
	}
	return config.Server{
		Name:     name,
		Protocol: config.ProtoTrojan,
		Address:  u.Hostname(),
		Port:     port,
		Password: u.User.Username(),
		SNI:      sni,
	}, nil
}

func parseSOCKS5(rest string) (config.Server, error) {
	u, err := url.Parse("socks5://" + rest)
	if err != nil {
		return config.Server{}, fmt.Errorf("socks5: %w", err)
	}
	port, err := toPort(u.Port())
	if err != nil {
		return config.Server{}, err
	}
	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	name := u.Fragment
	if name == "" {
		name = u.Hostname()
	}
	return config.Server{
		Name:     name,
		Protocol: config.ProtoSOCKS5,
		Address:  u.Hostname(),
		Port:     port,
		Username: user,
		Password: pass,
	}, nil
}

func parseHTTP(rest string) (config.Server, error) {
	s, err := parseSOCKS5(strings.Replace(rest, "/", "/", 1))
	if err != nil {
		return config.Server{}, err
	}
	s.Protocol = config.ProtoHTTP
	return s, nil
}

func splitHostPort(s string) (string, uint16, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, fmt.Errorf("sub: missing port in %q", s)
	}
	host := strings.Trim(s[:i], "[]")
	port, err := toPort(s[i+1:])
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func toPort(v any) (uint16, error) {
	var n int64
	switch x := v.(type) {
	case string:
		i, err := strconv.ParseInt(strings.TrimSpace(x), 10, 32)
		if err != nil {
			return 0, fmt.Errorf("bad port %q", x)
		}
		n = i
	case float64:
		n = int64(x)
	case int:
		n = int64(x)
	case json.Number:
		i, err := x.Int64()
		if err != nil {
			return 0, fmt.Errorf("bad port %q", x.String())
		}
		n = i
	case nil:
		return 0, errors.New("missing port")
	default:
		return 0, fmt.Errorf("unsupported port type %T", v)
	}
	if n <= 0 || n > 65535 {
		return 0, fmt.Errorf("port out of range: %d", n)
	}
	return uint16(n), nil
}

func decodeBase64(s string) ([]byte, error) {
	// strip every kind of whitespace first; subscriptions wrap lines
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t', ' ':
			return -1
		}
		return r
	}, s)
	// url-safe alphabet to standard
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	// restore padding
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	dec, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return dec, nil
	}
	// some generators emit raw (unpadded) url-safe strings
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
