//go:build with_utls

package main

import (
	"context"
	"fmt"
	"net"
	"time"

	tls2 "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

func main() {
	const (
		addr = "152.175.116.164:8080"
		sni  = "kinde.com"
		pbk  = "u_QJV_cSdElXkI92rsQ5A_b-MQogfr3MKUxo2Seq9kI"
		sid  = "6ba85179e30d4fc2"
	)

	cfg, err := tls2.NewRealityClient(
		context.Background(), nil, addr,
		option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: sni,
			Reality: &option.OutboundRealityOptions{
				PublicKey: pbk,
				ShortID:   sid,
			},
			UTLS: &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: "chrome",
			},
		},
	)
	if err != nil {
		fmt.Println("create:", err)
		return
	}
	fmt.Println("create: ok")

	for i := 1; i <= 3; i++ {
		raw, err := net.DialTimeout("tcp", addr, 8*time.Second)
		if err != nil {
			fmt.Printf("try %d dial: %v\n", i, err)
			continue
		}
		rc := cfg.(*tls2.RealityClientConfig)
		conn, err := rc.Client(raw)
		if err != nil {
			fmt.Printf("try %d handshake: %v\n", i, err)
			raw.Close()
			continue
		}
		st := conn.ConnectionState()
		fmt.Printf("try %d OK  version=0x%04x  suite=0x%04x  sni=%s\n",
			i, st.Version, st.CipherSuite, st.ServerName)
		conn.Close()
		time.Sleep(500 * time.Millisecond)
	}
}
