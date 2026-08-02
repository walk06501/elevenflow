// Smoke test internal/webview2bridge:
//   - Tạo provider giả (1 proxy fixed, không gọi server)
//   - Run pool với 2 worker, vài chunks
//   - In progress + kết quả
//
// Mục đích: validate package skeleton trước khi integrate vào Wails app.
//
// Usage:
//   go run ./cmd/webview2bridge-test -text "Đoạn text dài để chia chunks…" \
//       -proxy "host:port:user:pass" -workers 2 -voice 21m00Tcm4TlvDq8ikWAM \
//       -model eleven_v3 -lang vi
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"elevenflow/internal/proxyserver"
	"elevenflow/internal/webview2bridge"
)

// fixedProvider impl ProxyProvider trả về 1 proxy URL cố định, không rotate.
// Dùng để smoke test pipeline mà không cần server proxy thật.
type fixedProvider struct {
	url string
}

func (p *fixedProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (webview2bridge.Lease, error) {
	return webview2bridge.Lease{URL: p.url, AcquiredAt: time.Now(), Generation: 1}, nil
}

func (p *fixedProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease webview2bridge.Lease, emit func(string)) (webview2bridge.Lease, error) {
	if emit != nil {
		emit("fixedProvider: cannot rotate (no server) — sleep 5s rồi reuse cùng IP")
	}
	select {
	case <-time.After(5 * time.Second):
	case <-ctx.Done():
		return webview2bridge.Lease{}, ctx.Err()
	}
	return webview2bridge.Lease{URL: p.url, AcquiredAt: time.Now(), Generation: oldLease.Generation + 1}, nil
}

func (p *fixedProvider) Release(workerID int, lease webview2bridge.Lease) {}

func parseProxyArg(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if strings.Contains(s, "://") {
		return s, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) == 4 {
		host, port, user, pass := parts[0], parts[1], parts[2], parts[3]
		return fmt.Sprintf("http://%s:%s@%s:%s", url.QueryEscape(user), url.QueryEscape(pass), host, port), nil
	}
	return "", fmt.Errorf("proxy format không hợp lệ: %q (host:port:user:pass)", s)
}

func main() {
	text := flag.String("text", "Đoạn 1: Xin chào, đây là dòng đầu tiên qua WebView2 bridge.\nĐoạn 2: Giờ là dòng số hai, sẽ thuộc chunk khác.", "Text TTS")
	maxChars := flag.Int("max", 80, "Chunk size (chars) — chỉnh nhỏ để test có nhiều chunks")
	workers := flag.Int("workers", 2, "Số WV2 worker song song")
	visible := flag.Bool("visible", false, "Hiện cửa sổ WV2")
	voice := flag.String("voice", "21m00Tcm4TlvDq8ikWAM", "Voice ID")
	model := flag.String("model", "eleven_v3", "Model ID")
	lang := flag.String("lang", "vi", "Language code")
	speed := flag.Float64("speed", 1.0, "Voice speed")
	out := flag.String("out", "", "Output dir (default: %TEMP%\\elevenflow-out)")
	proxyArg := flag.String("proxy", "", "Proxy fixed URL (bypass server). Để trống = dùng SharedCurrentProvider.")
	useServer := flag.Bool("server", true, "Dùng proxyserver.Default() (SharedCurrentProvider). Chỉ dùng -proxy khi muốn test fixed.")
	flag.Parse()

	if *out == "" {
		*out = filepath.Join(os.TempDir(), "elevenflow-out")
	}

	var provider webview2bridge.ProxyProvider
	if *proxyArg != "" {
		upstream, err := parseProxyArg(*proxyArg)
		if err != nil {
			log.Fatalf("invalid -proxy: %v", err)
		}
		provider = &fixedProvider{url: upstream}
		fmt.Printf("[setup] dùng fixedProvider: %s\n", upstream)
	} else if *useServer {
		client := proxyserver.Default()
		provider = webview2bridge.NewPoolProvider(client)
		fmt.Printf("[setup] dùng PoolProvider (proxyserver.Default), session=%s\n", client.SessionID())
	} else {
		log.Fatalf("phải có -proxy hoặc -server=true")
	}

	cfg := webview2bridge.Config{
		NumWorkers:   *workers,
		MaxChars:     *maxChars,
		OutputDir:    *out,
		Visible:      *visible,
		Voice:        *voice,
		Model:        *model,
		LanguageCode: *lang,
		Speed:        *speed,
		Provider:     provider,
		Emit: func(workerID, chunkID int, phase, message string, done, total int) {
			fmt.Printf("[%-6s] %s\n", phase, message)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	results, err := webview2bridge.Run(ctx, *text, cfg)
	if err != nil {
		log.Fatalf("Run: %v", err)
	}

	fmt.Println("\n=== KẾT QUẢ ===")
	okCount := 0
	for _, r := range results {
		mark := "FAIL"
		if r.OK {
			mark = "OK"
			okCount++
		}
		fmt.Printf("  Chunk %d (worker %d, %d attempts, %d bytes): %s — %s\n",
			r.ID+1, r.WorkerID+1, r.Attempts, r.Bytes, mark, r.Message)
	}
	fmt.Printf("Tổng: %d/%d OK\n", okCount, len(results))
	if okCount != len(results) {
		os.Exit(2)
	}
}
