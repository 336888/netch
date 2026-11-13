package main

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

func main() {
	c := &dns.Client{Timeout: 5 * time.Second}

	m := new(dns.Msg)
	m.SetQuestion("api.ipify.org.", dns.TypeA)

	start := time.Now()
	r, _, err := c.Exchange(m, "127.0.0.1:11053")
	first := time.Since(start)
	if err != nil {
		fmt.Println("first query failed:", err)
		return
	}
	fmt.Printf("first  %v  answers=%d\n", first, len(r.Answer))
	for _, a := range r.Answer {
		if ar, ok := a.(*dns.A); ok {
			fmt.Println("  ->", ar.A.String())
		}
	}

	start = time.Now()
	r2, _, err := c.Exchange(m, "127.0.0.1:11053")
	second := time.Since(start)
	if err != nil {
		fmt.Println("second query failed:", err)
		return
	}
	fmt.Printf("second %v  answers=%d  (cache hit if much faster)\n", second, len(r2.Answer))
}
