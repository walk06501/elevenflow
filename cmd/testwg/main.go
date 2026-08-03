// Standalone connectivity test: does this VPS actually let a userspace
// WireGuard tunnel to a NordVPN server complete a handshake and pass real
// traffic, and does that hold up with several tunnels open at once under
// the SAME account (one private key)? Answers both open questions before
// building the full WireGuard-based proxy provider — neither can be
// assumed without checking directly (UDP reachability is network/VPS
// specific, and NordVPN's per-account concurrent-session limit, if any,
// isn't documented anywhere public).
//
// Usage:
//
//	go run ./cmd/testwg -token <ELEVEN_NORDVPN_TOKEN> -count 8
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type nordCreds struct {
	NordlynxPrivateKey string `json:"nordlynx_private_key"`
}

type nordServer struct {
	Hostname     string `json:"hostname"`
	Station      string `json:"station"`
	Load         int    `json:"load"`
	Status       string `json:"status"`
	Technologies []struct {
		Identifier string `json:"identifier"`
		Metadata   []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"metadata"`
	} `json:"technologies"`
}

type tunnelResult struct {
	idx       int
	hostname  string
	handshake bool
	exitIP    string
	err       error
	elapsed   time.Duration
}

func main() {
	token := flag.String("token", os.Getenv("ELEVEN_NORDVPN_TOKEN"), "NordVPN access token")
	count := flag.Int("count", 1, "how many tunnels to open concurrently (same account/private key, different servers)")
	stagger := flag.Duration("stagger", 0, "delay between starting each tunnel (0 = all at once) — tests burst-vs-hard-cap")
	hold := flag.Duration("hold", 0, "keep each successful tunnel open this long before closing it — so staggered starts still overlap in time")
	hosts := flag.String("hosts", "", "comma-separated hostnames to use instead of auto-picking (repeats allowed) — tests whether it's a per-server issue vs a per-account concurrent cap")
	recommend := flag.Bool("recommend", false, "use /v1/servers/recommendations (NordVPN's own curated pick) instead of the general /v1/servers list")
	flag.Parse()
	if *token == "" {
		log.Fatal("need -token or ELEVEN_NORDVPN_TOKEN")
	}

	fmt.Println("1. Fetching WireGuard private key from NordVPN credentials API...")
	privKeyB64, err := fetchPrivateKey(*token)
	if err != nil {
		log.Fatalf("   FAILED: %v", err)
	}
	privHex, err := keyToHex(privKeyB64)
	if err != nil {
		log.Fatalf("   bad private key: %v", err)
	}

	var servers []serverPick
	if *hosts != "" {
		fmt.Printf("2. Looking up explicit hostnames: %s\n", *hosts)
		all, err := fetchAllCandidates()
		if err != nil {
			log.Fatalf("   FAILED: %v", err)
		}
		for _, h := range strings.Split(*hosts, ",") {
			h = strings.TrimSpace(h)
			s, ok := all[h]
			if !ok {
				log.Fatalf("   hostname %q not found in current online wireguard_udp server list", h)
			}
			servers = append(servers, s)
			fmt.Printf("   %s (%s) load=%d%%\n", s.hostname, s.station, s.load)
		}
	} else if *recommend {
		fmt.Println("2. Fetching /v1/servers/recommendations (NordVPN's own curated pick, capped at 10 regardless of limit)...")
		servers, err = fetchRecommended(*token, *count)
		if err != nil {
			log.Fatalf("   FAILED: %v", err)
		}
		for _, s := range servers {
			fmt.Printf("   %s (%s) load=%d%%\n", s.hostname, s.station, s.load)
		}
	} else {
		fmt.Printf("2. Fetching server list, picking %d distinct lowest-load online WireGuard servers...\n", *count)
		servers, err = fetchServers(*count)
		if err != nil {
			log.Fatalf("   FAILED: %v", err)
		}
		for _, s := range servers {
			fmt.Printf("   %s (%s) load=%d%%\n", s.hostname, s.station, s.load)
		}
	}

	if *stagger > 0 {
		fmt.Printf("\n3. Opening %d tunnels, staggered %s apart, under the SAME private key...\n\n", len(servers), *stagger)
	} else {
		fmt.Printf("\n3. Opening %d tunnels concurrently (all at once) under the SAME private key...\n\n", len(servers))
	}
	var wg sync.WaitGroup
	results := make([]tunnelResult, len(servers))
	for i, s := range servers {
		wg.Add(1)
		go func(i int, s serverPick) {
			defer wg.Done()
			results[i] = runTunnel(i, privHex, s, *hold)
		}(i, s)
		if *stagger > 0 {
			time.Sleep(*stagger)
		}
	}
	wg.Wait()

	fmt.Println("\n=== KẾT QUẢ ===")
	ok := 0
	for _, r := range results {
		status := "FAIL"
		detail := ""
		if r.err != nil {
			detail = r.err.Error()
		} else if r.handshake && r.exitIP != "" {
			status = "OK"
			ok++
			detail = fmt.Sprintf("exitIP=%s (%.1fs)", r.exitIP, r.elapsed.Seconds())
		} else {
			detail = "no handshake"
		}
		fmt.Printf("  [%d] %-24s %-4s %s\n", r.idx, r.hostname, status, detail)
	}
	fmt.Printf("\nTổng: %d/%d tunnel thành công đồng thời (cùng 1 tài khoản/private key)\n", ok, len(results))
	if ok != len(results) {
		os.Exit(1)
	}
}

type serverPick struct {
	hostname string
	station  string
	pubHex   string
	load     int
}

func runTunnel(idx int, privHex string, s serverPick, hold time.Duration) tunnelResult {
	res := tunnelResult{idx: idx, hostname: s.hostname}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.5.0.2")},
		[]netip.Addr{netip.MustParseAddr("103.86.96.100")},
		1420,
	)
	if err != nil {
		res.err = fmt.Errorf("create tun: %w", err)
		return res
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()

	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s:51820\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		privHex, s.pubHex, s.station,
	)
	if err := dev.IpcSet(ipc); err != nil {
		res.err = fmt.Errorf("ipc set: %w", err)
		return res
	}
	if err := dev.Up(); err != nil {
		res.err = fmt.Errorf("device up: %w", err)
		return res
	}

	start := time.Now()
	for i := 0; i < 16; i++ {
		time.Sleep(500 * time.Millisecond)
		info, err := dev.IpcGet()
		if err != nil {
			continue
		}
		if strings.Contains(info, "last_handshake_time_sec=") && !strings.Contains(info, "last_handshake_time_sec=0\n") {
			res.handshake = true
			break
		}
	}
	if !res.handshake {
		res.err = fmt.Errorf("no handshake after 8s")
		return res
	}

	client := &http.Client{
		Transport: &http.Transport{DialContext: tnet.DialContext},
		Timeout:   15 * time.Second,
	}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		res.err = fmt.Errorf("http through tunnel: %w", err)
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	res.exitIP = strings.TrimSpace(string(body))
	res.elapsed = time.Since(start)
	if hold > 0 {
		time.Sleep(hold)
	}
	return res
}

func keyToHex(b64Key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func fetchPrivateKey(token string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.nordvpn.com/v1/users/services/credentials", nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth("token", token)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	var c nordCreds
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return "", err
	}
	if c.NordlynxPrivateKey == "" {
		return "", fmt.Errorf("empty nordlynx_private_key in response")
	}
	return c.NordlynxPrivateKey, nil
}

// fetchServers uses the plain (unauthenticated) full server list, same
// endpoint already confirmed working earlier — /v1/servers/recommendations
// is capped at 10 results server-side regardless of the requested limit,
// so it's not used here. Returns the n lowest-load distinct servers.
func fetchServers(n int) ([]serverPick, error) {
	all, err := fetchAllCandidates()
	if err != nil {
		return nil, err
	}
	picks := make([]serverPick, 0, len(all))
	for _, s := range all {
		picks = append(picks, s)
	}
	sort.Slice(picks, func(i, j int) bool { return picks[i].load < picks[j].load })
	if n > len(picks) {
		n = len(picks)
	}
	return picks[:n], nil
}

// fetchRecommended uses NordVPN's own curated /v1/servers/recommendations
// endpoint (needs the account token) instead of the general /v1/servers
// list — confirmed capped at 10 results regardless of the requested
// limit. Testing the theory that these curated picks behave differently
// under concurrent use than the general list.
func fetchRecommended(token string, n int) ([]serverPick, error) {
	url := "https://api.nordvpn.com/v1/servers/recommendations?filters%5Bservers_technologies%5D%5Bidentifier%5D=wireguard_udp&limit=" + fmt.Sprint(n)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token:"+token)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	var servers []nordServer
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		return nil, err
	}
	var picks []serverPick
	for _, s := range servers {
		var pubKey string
		for _, t := range s.Technologies {
			if t.Identifier != "wireguard_udp" {
				continue
			}
			for _, m := range t.Metadata {
				if m.Name == "public_key" {
					pubKey = m.Value
				}
			}
		}
		if pubKey == "" {
			continue
		}
		pubHex, err := keyToHex(pubKey)
		if err != nil {
			continue
		}
		picks = append(picks, serverPick{hostname: s.Hostname, station: s.Station, pubHex: pubHex, load: s.Load})
	}
	if len(picks) == 0 {
		return nil, fmt.Errorf("no wireguard_udp servers in recommendations response")
	}
	return picks, nil
}

// fetchAllCandidates returns every online wireguard_udp-capable server,
// keyed by hostname.
func fetchAllCandidates() (map[string]serverPick, error) {
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Get("https://api.nordvpn.com/v1/servers?limit=0")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	var servers []nordServer
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		return nil, err
	}

	out := map[string]serverPick{}
	for _, s := range servers {
		if s.Status != "online" {
			continue
		}
		var pubKey string
		for _, t := range s.Technologies {
			if t.Identifier != "wireguard_udp" {
				continue
			}
			for _, m := range t.Metadata {
				if m.Name == "public_key" {
					pubKey = m.Value
				}
			}
		}
		if pubKey == "" {
			continue
		}
		pubHex, err := keyToHex(pubKey)
		if err != nil {
			continue
		}
		out[s.Hostname] = serverPick{hostname: s.Hostname, station: s.Station, pubHex: pubHex, load: s.Load}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no online wireguard_udp servers found")
	}
	return out, nil
}
