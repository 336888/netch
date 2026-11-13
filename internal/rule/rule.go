// Package rule decides whether a connection goes direct, through the proxy,
// or gets rejected. Rules are evaluated top to bottom, first match wins.
package rule

import (
	"fmt"
	"net/netip"
	"strings"
)

type Action string

const (
	ActionProxy  Action = "proxy"
	ActionDirect Action = "direct"
	ActionReject Action = "reject"
)

type Meta struct {
	Domain  string
	DestIP  netip.Addr
	Port    uint16
	Process string
}

type Type string

const (
	TypeDomainSuffix  Type = "domain-suffix"
	TypeDomainKeyword Type = "domain-keyword"
	TypeDomainFull    Type = "domain-full"
	TypeIPCIDR        Type = "ip-cidr"
	TypeIPCIDR6       Type = "ip-cidr6"
	TypeProcessName   Type = "process-name"
	TypeProcessPath   Type = "process-path"
	TypeDstPort       Type = "dst-port"
	TypeFinal         Type = "final"
)

type Rule struct {
	Type   Type   `json:"type"`
	Value  string `json:"value"`
	Action Action `json:"action"`
	Note   string `json:"note,omitempty"`

	prefix netip.Prefix
	port   uint16
}

func (r *Rule) prepare() error {
	switch r.Type {
	case TypeIPCIDR, TypeIPCIDR6:
		p, err := netip.ParsePrefix(r.Value)
		if err != nil {
			return fmt.Errorf("rule %s %q: %w", r.Type, r.Value, err)
		}
		r.prefix = p
	case TypeDstPort:
		var n uint16
		if _, err := fmt.Sscanf(r.Value, "%d", &n); err != nil {
			return fmt.Errorf("rule dst-port %q: %w", r.Value, err)
		}
		r.port = n
	case TypeFinal:
		// no value needed
	}
	switch r.Action {
	case ActionProxy, ActionDirect, ActionReject:
	default:
		return fmt.Errorf("rule %s: unknown action %q", r.Type, r.Action)
	}
	return nil
}

type Matcher struct {
	rules []Rule
}

func New(rules []Rule) (*Matcher, error) {
	out := make([]Rule, 0, len(rules))
	for i := range rules {
		r := rules[i]
		if err := r.prepare(); err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		out = append(out, r)
	}
	return &Matcher{rules: out}, nil
}

// Match returns the first matching action. When nothing matches, proxy is used
// so traffic is never silently leaked outside the tunnel.
func (m *Matcher) Match(meta Meta) (Action, string) {
	host := strings.ToLower(strings.TrimSuffix(meta.Domain, "."))
	proc := strings.ToLower(meta.Process)

	for _, r := range m.rules {
		switch r.Type {
		case TypeDomainSuffix:
			v := strings.ToLower(strings.TrimPrefix(r.Value, "."))
			if host == v || strings.HasSuffix(host, "."+v) {
				return r.Action, r.Note
			}
		case TypeDomainKeyword:
			if strings.Contains(host, strings.ToLower(r.Value)) {
				return r.Action, r.Note
			}
		case TypeDomainFull:
			if host == strings.ToLower(r.Value) {
				return r.Action, r.Note
			}
		case TypeIPCIDR, TypeIPCIDR6:
			if meta.DestIP.IsValid() && r.prefix.Contains(meta.DestIP) {
				return r.Action, r.Note
			}
		case TypeProcessName:
			if proc != "" && strings.EqualFold(proc, r.Value) {
				return r.Action, r.Note
			}
		case TypeProcessPath:
			if meta.Process != "" && strings.EqualFold(meta.Process, r.Value) {
				return r.Action, r.Note
			}
		case TypeDstPort:
			if meta.Port == r.port {
				return r.Action, r.Note
			}
		case TypeFinal:
			return r.Action, r.Note
		}
	}
	return ActionProxy, ""
}

// Len reports how many rules are loaded.
func (m *Matcher) Len() int { return len(m.rules) }

// Default returns a sane starter ruleset for Chinese users: domestic traffic
// direct, everything else through the proxy.
func Default() []Rule {
	return []Rule{
		{Type: TypeProcessName, Value: "netease.exe", Action: ActionDirect, Note: "netease"},
		{Type: TypeProcessName, Value: "qq.exe", Action: ActionDirect, Note: "qq"},
		{Type: TypeProcessName, Value: "wechat.exe", Action: ActionDirect, Note: "wechat"},
		{Type: TypeDomainSuffix, Value: "cn", Action: ActionDirect, Note: "cn tld"},
		{Type: TypeDomainSuffix, Value: "qq.com", Action: ActionDirect},
		{Type: TypeDomainSuffix, Value: "taobao.com", Action: ActionDirect},
		{Type: TypeDomainSuffix, Value: "jd.com", Action: ActionDirect},
		{Type: TypeDomainSuffix, Value: "bilibili.com", Action: ActionDirect},
		{Type: TypeDomainSuffix, Value: "zhihu.com", Action: ActionDirect},
		{Type: TypeDomainSuffix, Value: "weibo.com", Action: ActionDirect},
		{Type: TypeDomainSuffix, Value: "aliyun.com", Action: ActionDirect},
		{Type: TypeDomainSuffix, Value: "tencent.com", Action: ActionDirect},
		{Type: TypeIPCIDR, Value: "10.0.0.0/8", Action: ActionDirect},
		{Type: TypeIPCIDR, Value: "172.16.0.0/12", Action: ActionDirect},
		{Type: TypeIPCIDR, Value: "192.168.0.0/16", Action: ActionDirect},
		{Type: TypeIPCIDR, Value: "127.0.0.0/8", Action: ActionDirect},
		{Type: TypeFinal, Action: ActionProxy},
	}
}
