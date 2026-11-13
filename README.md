# netch-go

A rewrite of [Netch](https://github.com/netchx/netch) in Go, built on Go 1.27.

Upstream is 14.7k lines of C# WinForms plus two C++ helpers. This repo rebuilds the
shell, proxy core, protocol backends, DNS, rules and GUI in Go, using `sing-*` libraries
for wire formats that already have solid Go implementations.

## Features

| Layer | State |
|---|---|
| SOCKS5 server (RFC 1928, user/pass, UDP ASSOCIATE) | done |
| HTTP proxy (CONNECT tunnel + plain forward) | done |
| Shadowsocks backend | done |
| Trojan backend (SHA224 + TLS) | done |
| VMess backend | done |
| VLESS backend | done |
| SOCKS5 upstream chain | done |
| Direct | done |
| Subscription parsing (`ss://` `vmess://` `vless://` `trojan://` `socks5://` `http://`) | done |
| TUN mode (sing-tun + gVisor) | done, `-tags with_gvisor` |
| Process mode (Linux nftables redirect) | done |
| Process mode (Windows, WinDivert) | done - needs WinDivert.dll |
| Local DNS server with cache | done |
| Rule-based routing (domain / IP / process / port) | done |
| System proxy (Windows / macOS / Linux) | done |
| Real-time connection log (text / JSON) | done |
| GUI (Walk, native Windows controls) | done |
| System tray with show/start/stop/quit | done |
| Latency test column | done |
| Connection detail table | done |
| Settings dialog | done |
| Rule file hot reload | done |
| Subscription auto-refresh | done |
| Cross-build 6 platforms | done |

## Build

```sh
go build -tags with_gvisor -trimpath -ldflags "-s -w" -o netch ./cmd/netch
```

Windows GUI (no console window):

```sh
GOOS=windows GOARCH=amd64 go build -tags with_gvisor -trimpath \
  -ldflags "-s -w -H=windowsgui" -o netch-gui.exe ./cmd/netch
```

Build matrix verified:

```
linux/amd64     13.5 MB
linux/arm64     12.5 MB
windows/amd64   18.9 MB
windows/arm64   17.2 MB
darwin/amd64    12.6 MB
darwin/arm64    11.7 MB
```

Without `-tags with_gvisor` TUN compiles but fails at runtime with
`tun.ErrGVisorNotIncluded`.

## Run

```sh
# CLI
./netch -c config.json -server my-node

# CLI with subscription merged in
./netch -c config.json -sub https://example.com/sub

# list parsed servers only
./netch -c config.json -sub sub.txt -list

# set OS proxy while running
./netch -c config.json -server my-node -sysproxy

# JSON connection log
./netch -c config.json -log-format json

# GUI
netch-gui.exe -gui -c config.json
```

## Config

```json
{
  "mode": "web",
  "servers": [
    { "name": "ss-tokyo", "protocol": "ss",
      "address": "1.2.3.4", "port": 8388,
      "method": "aes-128-gcm", "password": "secret" },

    { "name": "trojan-us", "protocol": "trojan",
      "address": "5.6.7.8", "port": 443,
      "password": "secret", "sni": "cdn.example.com" },

    { "name": "vmess-hk", "protocol": "vmess",
      "address": "9.9.9.9", "port": 8443,
      "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      "method": "auto", "sni": "example.com", "network": "ws" },

    { "name": "direct", "protocol": "direct" }
  ],
  "local": {
    "socks_addr": "127.0.0.1:1080",
    "http_addr":  "127.0.0.1:1081"
  },
  "dns": {
    "enabled": true,
    "listen": "127.0.0.1:53",
    "remote": "1.1.1.1",
    "cache_sec": 600
  },
  "rules": { "enabled": true, "file": "" },
  "tun": { "name": "Netch", "mtu": 1500, "stack": "gvisor", "auto_route": true },
  "log_level": "info",
  "timeout": 30
}
```

`timeout` accepts seconds (number) or a duration string (`"30s"`).

Modes: `web` (SOCKS5 + HTTP), `tun`, `process`, `share`.

## Rules

First match wins. Default ruleset covers common Chinese sites (direct) and falls
through to proxy.

```json
[
  { "type": "process-name",   "value": "qq.exe",       "action": "direct" },
  { "type": "domain-suffix",  "value": "taobao.com",   "action": "direct" },
  { "type": "domain-keyword", "value": "analytics",    "action": "reject" },
  { "type": "ip-cidr",        "value": "10.0.0.0/8",   "action": "direct" },
  { "type": "dst-port",       "value": "25",           "action": "reject" },
  { "type": "final",                                   "action": "proxy" }
]
```

Types: `domain-suffix`, `domain-keyword`, `domain-full`, `ip-cidr`, `ip-cidr6`,
`process-name`, `process-path`, `dst-port`, `final`.
Actions: `proxy`, `direct`, `reject`.

## Verified

DNS server (first query hits upstream, second hits cache):

```
first  12.355565ms  answers=3
  -> 104.26.12.205
  -> 104.26.13.205
  -> 172.67.74.152
second 395.281µs    answers=3
```

Rule routing:

```
socks5  direct 127.0.0.1:11081      5001ms up=79   down=175
socks5  direct www.qq.com:443        472ms up=717  down=7778
socks5  proxy  api.ipify.org:443     234ms up=775  down=3551
```

Connection log (text):

```
03:20:15.060 socks5 direct www.qq.com:443       472ms up=717 down=7778
03:20:15.543 socks5 proxy  api.ipify.org:443    234ms up=775 down=3551
```

Connection log (JSON):

```json
{"t":"2026-11-14T03:17:33.924+08:00","proto":"socks5","action":"proxy",
 "target":"api.ipify.org:443","up":775,"down":3574,"dur_ms":177}
```

Subscription parsing:

```
$ ./netch -c config.json -sub sub.txt -list
 1  ss-test    ss       127.0.0.1:18388  sni=
 2  trojan-test trojan   127.0.0.1:18443  sni=example.com
 3  node-a     ss       1.2.3.4:8388      sni=
 4  node-b     trojan   5.6.7.8:443       sni=x.com
```

## Layout

```
cmd/netch/            entry point, flags, signals, mode dispatch
internal/config/      config schema, defaults, validation
internal/logx/        slog handler with compact timestamps
internal/connlog/     per-connection events, stats, text/JSON sinks
internal/proxy/       SOCKS5 (TCP+UDP), HTTP proxy, relay
internal/outbound/    direct, socks5, ss, trojan, vmess, vless
internal/tunmode/     TUN device + gVisor stack + flow handler
internal/processmode/ nftables redirect (Linux) / WinDivert (Windows, pending)
internal/route/       route add/del, default gateway lookup
internal/dnsx/        local DNS server with TTL cache
internal/rule/        rule matcher, default ruleset
internal/sub/         share link + subscription parsing
internal/sysproxy/    OS proxy toggle
internal/gui/         Walk main window (windows build tag)
```

## Windows Process mode

Two paths exist:

1. **WinDivert** (`internal/processmode`) — drops or passes packets per process
   based on the rule matcher. Transparent proxying is not possible here: that
   needs a user-mode TCP stack.
2. **TUN** — full tunnelling, use this when you need every connection proxied.

WinDivert requires two files next to the executable:

```
WinDivert.dll
WinDivert64.sys
```

Download from https://github.com/basil00/WinDivert/releases (extract `x64/`).

## Windows process routing

The PID lookup layer (`internal/procmap`) is implemented:
`GetExtendedTcpTable` + `QueryFullProcessImageName` resolve a 4-tuple to a
process name with no kernel driver and no DLL dependency.

What it cannot do on its own: intercept a `connect()` before the socket leaves
the process. TUN sees packets after they left the app, so the source address is
the virtual adapter, not the real process. Per-process routing on Windows
therefore needs one of:

1. WinDivert with a user-mode TCP stack (gVisor) behind it — ~600 lines, needs
   `WinDivert.dll` and `WinDivert64.sys` shipped next to the exe
2. A kernel driver like upstream Netch's `nfapi.dll`

`procmap` is the piece both paths need; it is ready.

## Roadmap

- Transparent proxy on top of WinDivert (needs gVisor in user space)
- Rule file hot reload
- GeoIP rule type
- Server latency test in the GUI
- TCP Fast Open and MPTCP toggles

## License

GPL-3.0, same as upstream.
