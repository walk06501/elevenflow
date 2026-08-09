// One-off diagnostic: try a single manually-supplied WireGuard config end to
// end (handshake + real HTTP round trip through the tunnel), with verbose
// IpcGet() dumps so a silent "no handshake" isn't a black box. Built to
// settle whether IPVanish's bulk-harvested key dump (ipvanish_servers.go)
// is dead because of something wrong in this codebase's WireGuard handling,
// or because the keys themselves are no longer valid server-side — a config
// registered fresh through IPVanish's own site, right before running this,
// is the only way to isolate that.
//
// Usage:
//
//	go run ./cmd/testonekey -priv <PRIVATE_KEY_B64> -pub <SERVER_PUBLIC_KEY_B64> -addr 100.96.1.97 -host 116.90.73.23 -port 51820
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// wgKeyToHex mirrors internal/webview2bridge's unexported helper of the
// same name (base64 WireGuard key -> hex, what IpcSet expects) - duplicated
// here rather than exported from that package just for this one-off tool.
func wgKeyToHex(b64Key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func main() {
	priv := flag.String("priv", "", "private key (base64)")
	pub := flag.String("pub", "", "server public key (base64)")
	addr := flag.String("addr", "", "tunnel address, no /32 suffix, e.g. 100.96.1.97")
	dns := flag.String("dns", "198.18.0.1", "DNS server")
	host := flag.String("host", "", "server endpoint host/IP")
	port := flag.String("port", "51820", "server endpoint port")
	timeout := flag.Duration("timeout", 15*time.Second, "how long to wait for a handshake before giving up")
	flag.Parse()

	if *priv == "" || *pub == "" || *addr == "" || *host == "" {
		log.Fatal("need -priv -pub -addr -host (see file header for full example)")
	}

	privHex, err := wgKeyToHex(*priv)
	if err != nil {
		log.Fatalf("bad private key: %v", err)
	}
	pubHex, err := wgKeyToHex(*pub)
	if err != nil {
		log.Fatalf("bad public key: %v", err)
	}

	fmt.Printf("Building tunnel: addr=%s dns=%s endpoint=%s:%s\n", *addr, *dns, *host, *port)

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(*addr)},
		[]netip.Addr{netip.MustParseAddr(*dns)},
		1420,
	)
	if err != nil {
		log.Fatalf("create tun: %v", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, "[wg] "))

	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s:%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		privHex, pubHex, *host, *port,
	)
	if err := dev.IpcSet(ipc); err != nil {
		log.Fatalf("ipc set: %v", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatalf("device up: %v", err)
	}
	defer dev.Close()

	fmt.Printf("Waiting up to %s for handshake...\n", *timeout)
	deadline := time.Now().Add(*timeout)
	handshakeOK := false
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		info, err := dev.IpcGet()
		if err != nil {
			fmt.Printf("IpcGet error: %v\n", err)
			continue
		}
		if strings.Contains(info, "last_handshake_time_sec=") && !strings.Contains(info, "last_handshake_time_sec=0\n") {
			handshakeOK = true
			fmt.Println("HANDSHAKE OK")
			break
		}
	}
	if !handshakeOK {
		fmt.Println("\nFinal device state (IpcGet):")
		info, _ := dev.IpcGet()
		fmt.Println(info)
		fmt.Println("\nRESULT: NO HANDSHAKE - server never responded to this fresh key either")
		os.Exit(1)
	}

	fmt.Println("Trying real HTTP round trip through tunnel...")
	client := &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext}, Timeout: 10 * time.Second}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		fmt.Printf("RESULT: handshake OK but data path failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	buf := make([]byte, 200)
	n, _ := resp.Body.Read(buf)
	fmt.Printf("RESULT: SUCCESS - tunnel IP response: %s\n", string(buf[:n]))
	_ = context.Background()
}
