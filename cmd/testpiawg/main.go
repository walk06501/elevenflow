// Standalone connectivity test for PIAWireGuardProvider's full Acquire
// path (token -> server pick -> keypair -> addKey -> tunnel -> real HTTP
// round trip) — same reasoning as cmd/testwg: don't trust this works
// until a real lease is proven end to end.
//
// Usage:
//
//	go run ./cmd/testpiawg -user <PIA_USERNAME> -pass <PIA_PASSWORD>
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/net/proxy"

	"elevenflow/internal/webview2bridge"
)

func main() {
	user := flag.String("user", os.Getenv("ELEVEN_PIA_USERNAME"), "PIA username")
	pass := flag.String("pass", os.Getenv("ELEVEN_PIA_PASSWORD"), "PIA password")
	flag.Parse()
	if *user == "" || *pass == "" {
		log.Fatal("need -user/-pass or ELEVEN_PIA_USERNAME/ELEVEN_PIA_PASSWORD")
	}

	fmt.Println("1. Building PIAWireGuardProvider (token + server list fetch)...")
	p, err := webview2bridge.NewPIAWireGuardProvider(*user, *pass)
	if err != nil {
		log.Fatalf("   FAILED: %v", err)
	}

	fmt.Println("2. Acquiring a lease (keypair -> addKey -> tunnel -> handshake -> data check)...")
	start := time.Now()
	lease, err := p.Acquire(context.Background(), 0, func(msg string) { fmt.Printf("   [emit] %s\n", msg) })
	if err != nil {
		log.Fatalf("   FAILED after %.1fs: %v", time.Since(start).Seconds(), err)
	}
	fmt.Printf("   OK in %.1fs — lease URL: %s\n", time.Since(start).Seconds(), lease.URL)

	fmt.Println("3. Confirming the local SOCKS5 bridge actually forwards real traffic...")
	// net/http's Transport.Proxy only understands http(s):// proxy
	// schemes natively — same reason LocalProxy.dialSOCKS5 in the main
	// pipeline uses golang.org/x/net/proxy's SOCKS5 client dialer plugged
	// into DialContext instead.
	proxyURL, err := url.Parse(lease.URL)
	if err != nil {
		log.Fatalf("   bad lease URL %q: %v", lease.URL, err)
	}
	dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, nil, &net.Dialer{Timeout: 10 * time.Second})
	if err != nil {
		log.Fatalf("   socks5 dialer: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
		},
		Timeout: 15 * time.Second,
	}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		log.Fatalf("   FAILED: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 200)
	n, _ := resp.Body.Read(buf)
	fmt.Printf("   SUCCESS — exit IP via local bridge: %s\n", string(buf[:n]))

	p.Release(0, lease)
	fmt.Println("\nAll good.")
}
