// Batch scanner cho 1 thư mục config IPVanish WireGuard (.conf) — kiểm tra
// TỪNG file có thật sự sống (handshake thật + 1 round trip HTTP thật qua
// tunnel) hay không, thay vì tin cậy chỉ vì file tồn tại.
//
// Lý do bắt buộc phải scan trước khi wire vào hệ thống: doc comment của
// IPVanishWireGuardProvider (internal/webview2bridge/ipvanish_wireguard_provider.go)
// đã ghi lại 1 lần thất bại thật — 1 đợt harvest 3555 config cùng lúc
// (2026-08-09) toàn bộ đều CHẾT (không handshake được dù code không đổi),
// gần như chắc chắn do đụng trần đăng ký key/thiết bị của IPVanish khi tạo
// hàng loạt trong 1 lần — trong khi 1 key đăng ký riêng lẻ ngay sau đó chạy
// được ngay. Không có gì đảm bảo 1 đợt harvest MỚI (thư mục configs này)
// không dính đúng lỗi tương tự — phải đo thật, không suy đoán từ số lượng
// file có sẵn.
//
// Usage:
//
//	go run ./cmd/scanipvanish -dir "D:\tv360-scanner\configs" -out live_ipvanish.go.txt
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type wgConfig struct {
	name       string // tên file (không .conf), dùng làm Name
	privB64    string
	address    string // đã strip /32
	dns        string
	pubB64     string
	endpointIP string
	port       string
}

var (
	reSection  = regexp.MustCompile(`^\[(\w+)\]`)
	reKeyValue = regexp.MustCompile(`^(\w+)\s*=\s*(.+)$`)
)

func parseConfig(path string) (wgConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return wgConfig{}, err
	}
	defer f.Close()

	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	cfg := wgConfig{name: name, port: "51820"}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := reSection.FindStringSubmatch(line); m != nil {
			section = m[1]
			continue
		}
		m := reKeyValue.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, val := m[1], strings.TrimSpace(m[2])
		switch {
		case section == "Interface" && key == "PrivateKey":
			cfg.privB64 = val
		case section == "Interface" && key == "Address":
			// "100.96.6.142/32" -> "100.96.6.142" (khớp format cột Address
			// đã dùng trong ipvanishServer struct hiện có).
			cfg.address = strings.SplitN(val, "/", 2)[0]
		case section == "Interface" && key == "DNS":
			cfg.dns = strings.TrimSpace(strings.SplitN(val, ",", 2)[0])
		case section == "Peer" && key == "PublicKey":
			cfg.pubB64 = val
		case section == "Peer" && key == "Endpoint":
			parts := strings.SplitN(val, ":", 2)
			cfg.endpointIP = parts[0]
			if len(parts) == 2 {
				cfg.port = parts[1]
			}
		}
	}
	if cfg.privB64 == "" || cfg.address == "" || cfg.pubB64 == "" || cfg.endpointIP == "" {
		return wgConfig{}, fmt.Errorf("thiếu field bắt buộc (privB64/address/pubB64/endpoint)")
	}
	if cfg.dns == "" {
		cfg.dns = "198.18.0.1" // khớp ipvanishDNS mặc định trong provider thật
	}
	return cfg, sc.Err()
}

func wgKeyToHex(b64Key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// probe: dựng tunnel thật, đợi handshake thật, rồi 1 round trip HTTP thật —
// ĐÚNG bài test IPVanishWireGuardProvider.tryOne() dùng trong production,
// không phải bài test nhẹ hơn — mục tiêu là biết chắc config này có sống
// được trong hệ thống thật hay không, không phải chỉ "handshake xong".
func probe(cfg wgConfig, handshakeTimeout, probeTimeout time.Duration) error {
	privHex, err := wgKeyToHex(cfg.privB64)
	if err != nil {
		return fmt.Errorf("bad private key: %w", err)
	}
	pubHex, err := wgKeyToHex(cfg.pubB64)
	if err != nil {
		return fmt.Errorf("bad public key: %w", err)
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(cfg.address)},
		[]netip.Addr{netip.MustParseAddr(cfg.dns)},
		1420,
	)
	if err != nil {
		return fmt.Errorf("create tun: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()

	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s:%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		privHex, pubHex, cfg.endpointIP, cfg.port,
	)
	if err := dev.IpcSet(ipc); err != nil {
		return fmt.Errorf("ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("device up: %w", err)
	}

	handshakeOK := false
	deadline := time.Now().Add(handshakeTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		info, err := dev.IpcGet()
		if err == nil && strings.Contains(info, "last_handshake_time_sec=") && !strings.Contains(info, "last_handshake_time_sec=0\n") {
			handshakeOK = true
			break
		}
	}
	if !handshakeOK {
		return fmt.Errorf("no handshake within %s", handshakeTimeout)
	}

	client := &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext}, Timeout: probeTimeout}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		return fmt.Errorf("data path check failed: %w", err)
	}
	resp.Body.Close()
	return nil
}

func main() {
	dir := flag.String("dir", "", "thư mục chứa các file .conf cần scan")
	concurrency := flag.Int("concurrency", 20, "số config test song song")
	handshakeTimeout := flag.Duration("handshake-timeout", 8*time.Second, "thời gian chờ handshake trước khi coi là chết")
	probeTimeout := flag.Duration("probe-timeout", 5*time.Second, "thời gian chờ 1 round trip HTTP qua tunnel")
	out := flag.String("out", "", "file để ghi các dòng ipvanishServer{...} của config SỐNG (mặc định chỉ in ra màn hình)")
	flag.Parse()

	if *dir == "" {
		log.Fatal("cần -dir")
	}

	files, err := filepath.Glob(filepath.Join(*dir, "*.conf"))
	if err != nil {
		log.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		log.Fatalf("không tìm thấy file .conf nào trong %s", *dir)
	}
	sort.Strings(files)
	fmt.Printf("Tìm thấy %d file .conf, bắt đầu scan (concurrency=%d, handshake-timeout=%s, probe-timeout=%s)...\n",
		len(files), *concurrency, *handshakeTimeout, *probeTimeout)

	type result struct {
		cfg  wgConfig
		live bool
		err  error
		dur  time.Duration
	}
	jobs := make(chan string, len(files))
	results := make(chan result, len(files))
	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				cfg, perr := parseConfig(path)
				if perr != nil {
					results <- result{cfg: wgConfig{name: filepath.Base(path)}, live: false, err: perr}
					continue
				}
				t0 := time.Now()
				perr = probe(cfg, *handshakeTimeout, *probeTimeout)
				results <- result{cfg: cfg, live: perr == nil, err: perr, dur: time.Since(t0)}
			}
		}()
	}
	for _, f := range files {
		jobs <- f
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()

	var live, dead []result
	done := 0
	_ = context.Background()
	for r := range results {
		done++
		status := "SỐNG"
		if !r.live {
			status = "CHẾT"
		}
		fmt.Printf("[%d/%d] %-28s %s (%.1fs)", done, len(files), r.cfg.name, status, r.dur.Seconds())
		if !r.live && r.err != nil {
			fmt.Printf(" — %v", r.err)
		}
		fmt.Println()
		if r.live {
			live = append(live, r)
		} else {
			dead = append(dead, r)
		}
	}

	fmt.Printf("\n=== KẾT QUẢ: %d/%d sống (%.0f%%), %d chết ===\n", len(live), len(files), 100*float64(len(live))/float64(len(files)), len(dead))

	sort.Slice(live, func(i, j int) bool { return live[i].cfg.name < live[j].cfg.name })

	var sb strings.Builder
	for _, r := range live {
		c := r.cfg
		fmt.Fprintf(&sb, "\t{Name: %q, PrivateKeyB64: %q, Address: %q, PublicKeyB64: %q, Host: %q, Port: %q},\n",
			c.name, c.privB64, c.address, c.pubB64, c.endpointIP, c.port)
	}

	if *out != "" {
		if err := os.WriteFile(*out, []byte(sb.String()), 0644); err != nil {
			log.Fatalf("ghi file %s: %v", *out, err)
		}
		fmt.Printf("Đã ghi %d dòng ipvanishServer{...} vào %s\n", len(live), *out)
	} else {
		fmt.Println("\n--- Dán các dòng sau vào ipvanishServerList (ipvanish_servers.go) ---")
		fmt.Print(sb.String())
	}
}
