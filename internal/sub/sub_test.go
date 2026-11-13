package sub

import (
	"encoding/base64"
	"testing"

	"github.com/netchx/netch-go/internal/config"
)

func TestParseSS(t *testing.T) {
	// ss://base64(method:password)@host:port#name
	auth := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:secret"))
	uri := "ss://" + auth + "@1.2.3.4:8388#tokyo"
	s, err := Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if s.Protocol != config.ProtoSS || s.Address != "1.2.3.4" || s.Port != 8388 {
		t.Fatalf("unexpected: %+v", s)
	}
	if s.Method != "aes-128-gcm" || s.Password != "secret" || s.Name != "tokyo" {
		t.Fatalf("auth mismatch: %+v", s)
	}
}

func TestParseSSLegacy(t *testing.T) {
	// ss://base64(method:password@host:port)
	raw := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@5.6.7.8:443"))
	s, err := Parse("ss://" + raw + "#legacy")
	if err != nil {
		t.Fatal(err)
	}
	if s.Address != "5.6.7.8" || s.Port != 443 || s.Method != "chacha20-ietf-poly1305" {
		t.Fatalf("unexpected: %+v", s)
	}
}

func TestParseTrojan(t *testing.T) {
	s, err := Parse("trojan://pass123@example.com:443?sni=cdn.example.com#node1")
	if err != nil {
		t.Fatal(err)
	}
	if s.Protocol != config.ProtoTrojan || s.Password != "pass123" {
		t.Fatalf("unexpected: %+v", s)
	}
	if s.SNI != "cdn.example.com" || s.Name != "node1" {
		t.Fatalf("sni/name mismatch: %+v", s)
	}
}

func TestParseVLESS(t *testing.T) {
	s, err := Parse("vless://11111111-2222-3333-4444-555555555555@8.8.8.8:443?type=ws&sni=x.com#v1")
	if err != nil {
		t.Fatal(err)
	}
	if s.Protocol != config.ProtoVLESS || s.UUID == "" || s.SNI != "x.com" {
		t.Fatalf("unexpected: %+v", s)
	}
}

func TestParseVMess(t *testing.T) {
	payload := `{"v":"2","ps":"vm1","add":"9.9.9.9","port":"8443","id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","net":"ws","host":"h.com","tls":"tls"}`
	uri := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))
	s, err := Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if s.Protocol != config.ProtoVMess || s.Address != "9.9.9.9" || s.Port != 8443 {
		t.Fatalf("unexpected: %+v", s)
	}
	if s.SNI != "h.com" || s.Name != "vm1" {
		t.Fatalf("sni/name mismatch: %+v", s)
	}
}

func TestParseListBase64(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw"))
	plain := "ss://" + auth + "@1.1.1.1:8388#a\n" +
		"trojan://pw@2.2.2.2:443#b\n"
	wrapped := base64.StdEncoding.EncodeToString([]byte(plain))
	list, err := ParseList([]byte(wrapped))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 servers, got %d", len(list))
	}
}
