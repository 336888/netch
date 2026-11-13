package rule

import (
	"net/netip"
	"testing"
)

func mustMatcher(t *testing.T, rules []Rule) *Matcher {
	t.Helper()
	m, err := New(rules)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDomainSuffix(t *testing.T) {
	m := mustMatcher(t, []Rule{
		{Type: TypeDomainSuffix, Value: "qq.com", Action: ActionDirect},
		{Type: TypeFinal, Action: ActionProxy},
	})
	cases := []struct {
		host string
		want Action
	}{
		{"www.qq.com", ActionDirect},
		{"qq.com", ActionDirect},
		{"notqq.com", ActionProxy},
		{"qq.com.evil.io", ActionProxy},
	}
	for _, c := range cases {
		got, _ := m.Match(Meta{Domain: c.host})
		if got != c.want {
			t.Errorf("%s: got %s want %s", c.host, got, c.want)
		}
	}
}

func TestIDNA(t *testing.T) {
	m := mustMatcher(t, []Rule{
		{Type: TypeDomainSuffix, Value: "中文.cn", Action: ActionDirect},
		{Type: TypeFinal, Action: ActionProxy},
	})
	// punycode form of 中文.cn
	got, _ := m.Match(Meta{Domain: "xn--fiq228c.cn"})
	if got != ActionDirect {
		t.Errorf("punycode form not matched: got %s", got)
	}
	got, _ = m.Match(Meta{Domain: "中文.cn"})
	if got != ActionDirect {
		t.Errorf("unicode form not matched: got %s", got)
	}
}

func TestIPCIDR(t *testing.T) {
	m := mustMatcher(t, []Rule{
		{Type: TypeIPCIDR, Value: "10.0.0.0/8", Action: ActionDirect},
		{Type: TypeFinal, Action: ActionProxy},
	})
	got, _ := m.Match(Meta{DestIP: netip.MustParseAddr("10.1.2.3")})
	if got != ActionDirect {
		t.Errorf("10.1.2.3: got %s", got)
	}
	got, _ = m.Match(Meta{DestIP: netip.MustParseAddr("11.1.2.3")})
	if got != ActionProxy {
		t.Errorf("11.1.2.3: got %s", got)
	}
}

func TestProcessName(t *testing.T) {
	m := mustMatcher(t, []Rule{
		{Type: TypeProcessName, Value: "qq.exe", Action: ActionDirect},
		{Type: TypeFinal, Action: ActionProxy},
	})
	got, _ := m.Match(Meta{Domain: "a.com", Process: "QQ.EXE"})
	if got != ActionDirect {
		t.Errorf("case insensitive match failed: got %s", got)
	}
}

func TestPort(t *testing.T) {
	m := mustMatcher(t, []Rule{
		{Type: TypeDstPort, Value: "25", Action: ActionReject},
		{Type: TypeFinal, Action: ActionProxy},
	})
	got, _ := m.Match(Meta{Domain: "smtp.example.com", Port: 25})
	if got != ActionReject {
		t.Errorf("port 25: got %s", got)
	}
}

func TestInvalidRule(t *testing.T) {
	_, err := New([]Rule{{Type: TypeIPCIDR, Value: "not-a-cidr"}})
	if err == nil {
		t.Error("expected error for bad CIDR")
	}
	_, err = New([]Rule{{Type: TypeFinal, Action: "nonsense"}})
	if err == nil {
		t.Error("expected error for bad action")
	}
}
