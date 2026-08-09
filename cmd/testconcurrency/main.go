// Concurrency probe for PIAWireGuardProvider and SurfsharkWireGuardProvider
// — same question already answered for NordVPN-WG (cmd/testwg,
// cmd/scanwgpools): does this account/key sustain more than one real
// WireGuard data path at once, using the REAL provider's own Acquire(),
// not a hand-rolled tunnel. Real handshake + one real HTTP round trip per
// lease (Acquire already does this internally), same as testwg.
//
// Usage:
//
//	go run ./cmd/testconcurrency -provider pia -user <PIA_USER> -pass <PIA_PASS> -count 10
//	go run ./cmd/testconcurrency -provider surfshark -key <SURFSHARK_PRIVATE_KEY> -count 10
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"elevenflow/internal/webview2bridge"
)

type acquirer interface {
	Acquire(ctx context.Context, workerID int, emit func(string)) (webview2bridge.Lease, error)
	Release(workerID int, lease webview2bridge.Lease)
}

func main() {
	providerName := flag.String("provider", "", "\"pia\", \"surfshark\", \"proton\", or \"ipvanish\"")
	user := flag.String("user", os.Getenv("ELEVEN_PIA_USERNAME"), "PIA username (provider=pia)")
	pass := flag.String("pass", os.Getenv("ELEVEN_PIA_PASSWORD"), "PIA password (provider=pia)")
	key := flag.String("key", os.Getenv("ELEVEN_SURFSHARK_PRIVATE_KEY"), "Surfshark private key (provider=surfshark)")
	protonUser := flag.String("proton-user", os.Getenv("ELEVEN_PROTON_USERNAME"), "ProtonVPN username (provider=proton)")
	protonPass := flag.String("proton-pass", os.Getenv("ELEVEN_PROTON_PASSWORD"), "ProtonVPN password (provider=proton)")
	count := flag.Int("count", 10, "how many leases to acquire concurrently, same account")
	hold := flag.Duration("hold", 5*time.Second, "keep each successful lease open this long before releasing")
	flag.Parse()

	var p acquirer
	var err error
	switch *providerName {
	case "pia":
		if *user == "" || *pass == "" {
			log.Fatal("need -user/-pass or ELEVEN_PIA_USERNAME/ELEVEN_PIA_PASSWORD")
		}
		fmt.Println("Building PIAWireGuardProvider...")
		p, err = webview2bridge.NewPIAWireGuardProvider(*user, *pass)
	case "surfshark":
		if *key == "" {
			log.Fatal("need -key or ELEVEN_SURFSHARK_PRIVATE_KEY")
		}
		fmt.Println("Building SurfsharkWireGuardProvider...")
		p, err = webview2bridge.NewSurfsharkWireGuardProvider(*key)
	case "proton":
		if *protonUser == "" || *protonPass == "" {
			log.Fatal("need -proton-user/-proton-pass or ELEVEN_PROTON_USERNAME/ELEVEN_PROTON_PASSWORD")
		}
		fmt.Println("Building ProtonVPNWireGuardProvider (SRP login + certificate registration)...")
		p, err = webview2bridge.NewProtonVPNWireGuardProvider(*protonUser, *protonPass)
	case "ipvanish":
		fmt.Println("Building IPVanishWireGuardProvider...")
		p, err = webview2bridge.NewIPVanishWireGuardProvider()
	default:
		log.Fatal("need -provider pia|surfshark|proton|ipvanish")
	}
	if err != nil {
		log.Fatalf("provider init failed: %v", err)
	}

	fmt.Printf("Acquiring %d leases concurrently, same account/key...\n\n", *count)

	type result struct {
		idx     int
		ok      bool
		elapsed time.Duration
		err     error
		lease   webview2bridge.Lease
	}
	results := make([]result, *count)
	var wg sync.WaitGroup
	for i := 0; i < *count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			t0 := time.Now()
			lease, err := p.Acquire(context.Background(), i, nil)
			results[i] = result{idx: i, ok: err == nil, elapsed: time.Since(t0), err: err, lease: lease}
		}(i)
	}
	wg.Wait()

	ok := 0
	for _, r := range results {
		status := "FAIL"
		detail := ""
		if r.ok {
			status = "OK"
			ok++
			detail = fmt.Sprintf("%.1fs", r.elapsed.Seconds())
		} else {
			detail = r.err.Error()
		}
		fmt.Printf("  [%d] %-4s %s\n", r.idx, status, detail)
	}
	fmt.Printf("\nTong: %d/%d dong thoi thanh cong (cung 1 tai khoan)\n", ok, *count)

	if *hold > 0 && ok > 0 {
		fmt.Printf("\nHolding %d successful leases for %s before releasing...\n", ok, *hold)
		time.Sleep(*hold)
	}
	for _, r := range results {
		if r.ok {
			p.Release(r.idx, r.lease)
		}
	}

	if ok != *count {
		os.Exit(1)
	}
}
