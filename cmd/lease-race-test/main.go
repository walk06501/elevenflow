// lease-race-test: gọi /api/proxy/lease song song từ N goroutine (cùng session
// hoặc khác session), assert rằng mọi lease_token KHÔNG trùng nhau.
//
// Usage:
//   go run ./cmd/lease-race-test [-workers N] [-sessions M] [-release] [-v]
//
//   -workers N   số goroutine lease song song trong mỗi session (mặc định 3)
//   -sessions M  số client session song song (mặc định 2) — mỗi session =
//                1 proxyserver.Client với sessionID riêng (UUID mới)
//   -release     sau khi assert, release tất cả lease → sạch DB
//   -v           verbose: in log countdown từng goroutine
//
// Exit 0 = pass (tất cả token duy nhất).
// Exit 2 = fail (trùng token — server bug hoặc race condition chưa fix).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"elevenflow/internal/proxyserver"
)

type leaseResult struct {
	sessionID string
	workerID  int
	token     string
	url       string
	elapsed   time.Duration
	err       error
}

func main() {
	workers   := flag.Int("workers",  3,    "goroutine per session")
	sessions  := flag.Int("sessions", 2,    "số session client song song")
	doRelease := flag.Bool("release", true, "release tất cả lease sau test")
	verbose   := flag.Bool("v",       false, "verbose log đếm ngược")
	flag.Parse()

	fmt.Printf("=== Lease race test: %d session × %d worker = %d concurrent leases ===\n",
		*sessions, *workers, (*workers)*(*sessions))

	clients := make([]*proxyserver.Client, *sessions)
	for s := range clients {
		clients[s] = proxyserver.Default()
		fmt.Printf("  Session %d: %s\n", s+1, clients[s].SessionID())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []leaseResult
	)

	start := time.Now()
	for s, c := range clients {
		for w := 0; w < *workers; w++ {
			wg.Add(1)
			go func(c *proxyserver.Client, s, w int) {
				defer wg.Done()
				t0 := time.Now()
				emit := func(msg string) {
					if *verbose {
						fmt.Printf("  [S%d W%d] %s\n", s+1, w+1, msg)
					}
				}
				resp, err := c.LeaseWithWait(ctx, "", emit)
				r := leaseResult{
					sessionID: c.SessionID(),
					workerID:  w,
					elapsed:   time.Since(t0),
					err:       err,
				}
				if err == nil {
					r.token = resp.LeaseToken
					r.url = resp.ProxyHTTP
					if r.url == "" {
						r.url = resp.ProxySOCKS5
					}
				}
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}(c, s, w)
		}
	}
	wg.Wait()
	fmt.Printf("\nTất cả hoàn tất trong %.1fs\n\n", time.Since(start).Seconds())

	// Print
	fmt.Printf("%-10s %-6s %-38s %s\n", "Session", "Worker", "LeaseToken", "URL")
	fmt.Println(repeat("-", 100))
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("  S%-8s W%-4d ERROR: %v\n", shortID(r.sessionID), r.workerID+1, r.err)
			continue
		}
		fmt.Printf("  S%-8s W%-4d %-38s %-30s (%.1fs)\n",
			shortID(r.sessionID), r.workerID+1, r.token, maskURL(r.url), r.elapsed.Seconds())
	}

	// Assert
	fmt.Println()
	tokenSeen := map[string]string{}
	urlSeen   := map[string]string{}
	failed    := false

	for _, r := range results {
		if r.err != nil {
			fmt.Printf("FAIL goroutine S%s W%d lỗi: %v\n", shortID(r.sessionID), r.workerID+1, r.err)
			failed = true
			continue
		}
		label := fmt.Sprintf("S%s W%d", shortID(r.sessionID), r.workerID+1)
		if prev, dup := tokenSeen[r.token]; dup {
			fmt.Printf("FAIL lease_token TRÙNG: %q nhận bởi %s VÀ %s\n", r.token, label, prev)
			failed = true
		} else {
			tokenSeen[r.token] = label
		}
		if prev, dup := urlSeen[r.url]; dup {
			// URL trùng = pool không đủ key cho tất cả worker song song.
			// WARN thôi vì có thể intentional (pool nhỏ hơn total workers).
			fmt.Printf("WARN proxy URL trùng (pool thiếu slot): %s nhận cùng URL với %s → %s\n",
				label, prev, maskURL(r.url))
		} else {
			urlSeen[r.url] = label
		}
	}

	fmt.Println()
	if failed {
		fmt.Printf("✗ FAIL — tìm thấy lease_token trùng (server chưa dùng SKIP LOCKED?)\n")
		if *doRelease {
			releaseAll(ctx, clients, results)
		}
		os.Exit(2)
	}
	fmt.Printf("✓ PASS — %d lease, %d token duy nhất, %d URL duy nhất\n",
		len(results), len(tokenSeen), len(urlSeen))
	if *doRelease {
		releaseAll(ctx, clients, results)
	}
}

func releaseAll(ctx context.Context, clients []*proxyserver.Client, results []leaseResult) {
	fmt.Println("\nReleasing tất cả lease…")
	sidMap := map[string]*proxyserver.Client{}
	for _, c := range clients {
		sidMap[c.SessionID()] = c
	}
	var wg sync.WaitGroup
	for _, r := range results {
		if r.err != nil || r.token == "" {
			continue
		}
		c, ok := sidMap[r.sessionID]
		if !ok {
			continue
		}
		wg.Add(1)
		go func(c *proxyserver.Client, t string) {
			defer wg.Done()
			rCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if err := c.Release(rCtx, t, false); err != nil {
				fmt.Printf("  release %s…: %v\n", t[:min(8, len(t))], err)
			} else {
				fmt.Printf("  released %s…\n", t[:min(8, len(t))])
			}
		}(c, r.token)
	}
	wg.Wait()
	fmt.Println("Done.")
}

func maskURL(u string) string {
	at, scheme := -1, -1
	for i, c := range u {
		if c == '/' && i+1 < len(u) && u[i+1] == '/' {
			scheme = i + 2
		}
		if c == '@' {
			at = i
		}
	}
	if scheme >= 0 && at > scheme {
		return u[:scheme] + "***@" + u[at+1:]
	}
	return u
}

func shortID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}

func repeat(s string, n int) string {
	out := make([]byte, n*len(s))
	for i := range out {
		out[i] = s[i%len(s)]
	}
	return string(out)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
