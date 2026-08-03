// Standalone connectivity test for SurfsharkWireGuardProvider's full
// Acquire path (resolve hostname -> tunnel -> handshake -> real HTTP
// round trip) — same reasoning as cmd/testwg and cmd/testpiawg: don't
// trust this works until a real lease is proven end to end.
//
// Usage:
//
//	go run ./cmd/testsurfshark -key <SURFSHARK_PRIVATE_KEY_B64>
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
	key := flag.String("key", os.Getenv("ELEVEN_SURFSHARK_PRIVATE_KEY"), "Surfshark WireGuard private key (base64)")
	flag.Parse()
	if *key == "" {
		log.Fatal("need -key or ELEVEN_SURFSHARK_PRIVATE_KEY")
	}

	fmt.Println("1. Building SurfsharkWireGuardProvider...")
	p, err := webview2bridge.NewSurfsharkWireGuardProvider(*key)
	if err != nil {
		log.Fatalf("   FAILED: %v", err)
	}

	fmt.Println("2. Acquiring a lease (resolve -> tunnel -> handshake -> data check)...")
	start := time.Now()
	lease, err := p.Acquire(context.Background(), 0, func(msg string) { fmt.Printf("   [emit] %s\n", msg) })
	if err != nil {
		log.Fatalf("   FAILED after %.1fs: %v", time.Since(start).Seconds(), err)
	}
	fmt.Printf("   OK in %.1fs — lease URL: %s\n", time.Since(start).Seconds(), lease.URL)

	fmt.Println("3. Confirming the local SOCKS5 bridge actually forwards real traffic...")
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
