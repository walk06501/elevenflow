// Batch scanner: finds NordVPN WireGuard "virtual server pool" groups that
// support multiple simultaneous connections per account (unlike ordinary
// dedicated servers, which only sustain ~1).
//
// Groups by WIREGUARD PUBLIC KEY, not station /24 subnet (an earlier,
// weaker proxy). Confirmed live (2026-08-05): NordVPN's entire WireGuard
// fleet is exactly 224 distinct public keys shared across 8803 online
// servers — every key is shared by at least 2 hostnames, so "same public
// key" IS "same backend", directly, not a guess. A /24 subnet can straddle
// more than one key group (mixed-in hostnames from a different backend
// sharing the same block), which is the likely reason an earlier subnet-
// based scan gave inconsistent results for the same subnet on different
// runs — servers sharing a key share a backend and should behave alike;
// servers merely sharing a subnet are not guaranteed to.
//
// Usage:
//
//	go run ./cmd/scanwgpools -token <ELEVEN_NORDVPN_TOKEN> -min-hosts 6 -max-groups 224
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

type serverPick struct {
	hostname string
	station  string
	pubHex   string
}

func main() {
	token := flag.String("token", os.Getenv("ELEVEN_NORDVPN_TOKEN"), "NordVPN access token")
	minHosts := flag.Int("min-hosts", 2, "only test public-key groups with at least this many hostnames (every key has >=2 live 2026-08-05, so 2 tests everything)")
	maxGroups := flag.Int("max-groups", 60, "test at most this many key groups (largest first), 0 = all ~224")
	perGroup := flag.Int("per-group", 10, "how many hostnames to test concurrently per key group")
	flag.Parse()
	if *token == "" {
		log.Fatal("need -token or ELEVEN_NORDVPN_TOKEN")
	}

	fmt.Println("1. Fetching WireGuard private key...")
	privKeyB64, err := fetchPrivateKey(*token)
	if err != nil {
		log.Fatalf("   FAILED: %v", err)
	}
	privHex, err := keyToHex(privKeyB64)
	if err != nil {
		log.Fatalf("   bad private key: %v", err)
	}

	fmt.Println("2. Fetching full server list, grouping by WireGuard public key...")
	byKey, err := fetchGroupedByKey()
	if err != nil {
		log.Fatalf("   FAILED: %v", err)
	}

	type keyGroup struct {
		pubHex string
		hosts  []serverPick
	}
	var groups []keyGroup
	for pubHex, hosts := range byKey {
		if len(hosts) >= *minHosts {
			groups = append(groups, keyGroup{pubHex, hosts})
		}
	}
	sort.Slice(groups, func(i, j int) bool { return len(groups[i].hosts) > len(groups[j].hosts) })
	if *maxGroups > 0 && len(groups) > *maxGroups {
		groups = groups[:*maxGroups]
	}
	fmt.Printf("   %d key groups to test (out of %d total, >= %d hosts each)\n\n", len(groups), len(byKey), *minHosts)

	type result struct {
		pubHex string
		total  int
		ok     int
		sample string
		groupN int
	}
	var results []result

	for i, entry := range groups {
		n := *perGroup
		if n > len(entry.hosts) {
			n = len(entry.hosts)
		}
		candidates := entry.hosts[:n]
		fmt.Printf("[%d/%d] testing key %s... (%d hosts, using %d)... ", i+1, len(groups), entry.pubHex[:12], len(entry.hosts), n)

		ok := testBatch(privHex, candidates)
		fmt.Printf("%d/%d OK\n", ok, n)
		results = append(results, result{
			pubHex: entry.pubHex,
			total:  n,
			ok:     ok,
			sample: candidates[0].hostname,
			groupN: len(entry.hosts),
		})

		// Brief pause between groups so we don't hammer NordVPN's API/infra
		// hard enough to trigger unrelated rate-limiting that would muddy
		// results (seen earlier: rapid-fire testing alone caused noise).
		time.Sleep(3 * time.Second)
	}

	fmt.Println("\n=== TỔNG KẾT — key group có đa phiên thật (ok >= 5/10) ===")
	goodCount := 0
	for _, r := range results {
		if r.ok >= 5 {
			goodCount++
			fmt.Printf("  GOOD  %s...  %d/%d  (nhóm có %d host, vd: %s)\n", r.pubHex[:16], r.ok, r.total, r.groupN, r.sample)
		}
	}
	fmt.Printf("\n%d/%d key group đã test là pool đa phiên thật\n", goodCount, len(results))

	fmt.Println("\n=== Toàn bộ kết quả ===")
	for _, r := range results {
		fmt.Printf("  %s...  %d/%d  (nhóm có %d host, vd: %s)\n", r.pubHex[:16], r.ok, r.total, r.groupN, r.sample)
	}
}

func testBatch(privHex string, candidates []serverPick) int {
	var wg sync.WaitGroup
	okCount := make([]bool, len(candidates))
	for i, s := range candidates {
		wg.Add(1)
		go func(i int, s serverPick) {
			defer wg.Done()
			okCount[i] = tryTunnel(privHex, s)
		}(i, s)
	}
	wg.Wait()
	n := 0
	for _, ok := range okCount {
		if ok {
			n++
		}
	}
	return n
}

func tryTunnel(privHex string, s serverPick) bool {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.5.0.2")},
		[]netip.Addr{netip.MustParseAddr("103.86.96.100")},
		1420,
	)
	if err != nil {
		return false
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()

	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s:51820\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		privHex, s.pubHex, s.station,
	)
	if err := dev.IpcSet(ipc); err != nil {
		return false
	}
	if err := dev.Up(); err != nil {
		return false
	}

	handshakeOK := false
	for i := 0; i < 16; i++ {
		time.Sleep(500 * time.Millisecond)
		info, err := dev.IpcGet()
		if err == nil && strings.Contains(info, "last_handshake_time_sec=") && !strings.Contains(info, "last_handshake_time_sec=0\n") {
			handshakeOK = true
			break
		}
	}
	if !handshakeOK {
		return false
	}

	client := &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext}, Timeout: 8 * time.Second}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
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
	var c struct {
		NordlynxPrivateKey string `json:"nordlynx_private_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return "", err
	}
	if c.NordlynxPrivateKey == "" {
		return "", fmt.Errorf("empty nordlynx_private_key in response")
	}
	return c.NordlynxPrivateKey, nil
}

// fetchGroupedByKey groups every online wireguard_udp server by its
// WireGuard public key (hex) instead of by station subnet — the public key
// IS the backend identity, so this is a direct grouping, not a proxy.
func fetchGroupedByKey() (map[string][]serverPick, error) {
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

	out := map[string][]serverPick{}
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
		out[pubHex] = append(out[pubHex], serverPick{hostname: s.Hostname, station: s.Station, pubHex: pubHex})
	}
	return out, nil
}
