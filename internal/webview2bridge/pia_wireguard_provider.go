package webview2bridge

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type piaWGServer struct {
	ip     string
	cn     string // certificate common name — required for addKey, see addKey's doc comment
	region string
}

// piaCACert is PIA's own custom root CA (ca.rsa.4096.crt), fetched from
// their official pia-foss/manual-connections reference scripts — the
// addKey endpoint's certificate chains to this, not a public CA, and not
// a self-signed leaf either. An earlier version of this file used
// InsecureSkipVerify based on a reverse-engineered tool that did the
// same, which turned out to be simply wrong: every addKey call failed
// with a bare TLS-level EOF until the connection was made exactly the
// way PIA's own scripts make it (see addKey's doc comment for the full
// story) — skipping verification was never actually required.
const piaCACert = `-----BEGIN CERTIFICATE-----
MIIHqzCCBZOgAwIBAgIJAJ0u+vODZJntMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNV
BAoTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIElu
dGVybmV0IEFjY2VzczEgMB4GA1UEAxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3Mx
IDAeBgNVBCkTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkB
FiBzZWN1cmVAcHJpdmF0ZWludGVybmV0YWNjZXNzLmNvbTAeFw0xNDA0MTcxNzQw
MzNaFw0zNDA0MTIxNzQwMzNaMIHoMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex
EzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNVBAoTF1ByaXZhdGUgSW50ZXJuZXQg
QWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UE
AxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBCkTF1ByaXZhdGUgSW50
ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkBFiBzZWN1cmVAcHJpdmF0ZWludGVy
bmV0YWNjZXNzLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVk
hjumaqBbL8aSgj6xbX1QPTfTd1qHsAZd2B97m8Vw31c/2yQgZNf5qZY0+jOIHULN
De4R9TIvyBEbvnAg/OkPw8n/+ScgYOeH876VUXzjLDBnDb8DLr/+w9oVsuDeFJ9K
V2UFM1OYX0SnkHnrYAN2QLF98ESK4NCSU01h5zkcgmQ+qKSfA9Ny0/UpsKPBFqsQ
25NvjDWFhCpeqCHKUJ4Be27CDbSl7lAkBuHMPHJs8f8xPgAbHRXZOxVCpayZ2SND
fCwsnGWpWFoMGvdMbygngCn6jA/W1VSFOlRlfLuuGe7QFfDwA0jaLCxuWt/BgZyl
p7tAzYKR8lnWmtUCPm4+BtjyVDYtDCiGBD9Z4P13RFWvJHw5aapx/5W/CuvVyI7p
Kwvc2IT+KPxCUhH1XI8ca5RN3C9NoPJJf6qpg4g0rJH3aaWkoMRrYvQ+5PXXYUzj
tRHImghRGd/ydERYoAZXuGSbPkm9Y/p2X8unLcW+F0xpJD98+ZI+tzSsI99Zs5wi
jSUGYr9/j18KHFTMQ8n+1jauc5bCCegN27dPeKXNSZ5riXFL2XX6BkY68y58UaNz
meGMiUL9BOV1iV+PMb7B7PYs7oFLjAhh0EdyvfHkrh/ZV9BEhtFa7yXp8XR0J6vz
1YV9R6DYJmLjOEbhU8N0gc3tZm4Qz39lIIG6w3FDAgMBAAGjggFUMIIBUDAdBgNV
HQ4EFgQUrsRtyWJftjpdRM0+925Y6Cl08SUwggEfBgNVHSMEggEWMIIBEoAUrsRt
yWJftjpdRM0+925Y6Cl08SWhge6kgeswgegxCzAJBgNVBAYTAlVTMQswCQYDVQQI
EwJDQTETMBEGA1UEBxMKTG9zQW5nZWxlczEgMB4GA1UEChMXUHJpdmF0ZSBJbnRl
cm5ldCBBY2Nlc3MxIDAeBgNVBAsTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAw
HgYDVQQDExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UEKRMXUHJpdmF0
ZSBJbnRlcm5ldCBBY2Nlc3MxLzAtBgkqhkiG9w0BCQEWIHNlY3VyZUBwcml2YXRl
aW50ZXJuZXRhY2Nlc3MuY29tggkAnS7684Nkme0wDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQ0FAAOCAgEAJsfhsPk3r8kLXLxY+v+vHzbr4ufNtqnL9/1Uuf8NrsCt
pXAoyZ0YqfbkWx3NHTZ7OE9ZRhdMP/RqHQE1p4N4Sa1nZKhTKasV6KhHDqSCt/dv
Em89xWm2MVA7nyzQxVlHa9AkcBaemcXEiyT19XdpiXOP4Vhs+J1R5m8zQOxZlV1G
tF9vsXmJqWZpOVPmZ8f35BCsYPvv4yMewnrtAC8PFEK/bOPeYcKN50bol22QYaZu
LfpkHfNiFTnfMh8sl/ablPyNY7DUNiP5DRcMdIwmfGQxR5WEQoHL3yPJ42LkB5zs
6jIm26DGNXfwura/mi105+ENH1CaROtRYwkiHb08U6qLXXJz80mWJkT90nr8Asj3
5xN2cUppg74nG3YVav/38P48T56hG1NHbYF5uOCske19F6wi9maUoto/3vEr0rnX
JUp2KODmKdvBI7co245lHBABWikk8VfejQSlCtDBXn644ZMtAdoxKNfR2WTFVEwJ
iyd1Fzx0yujuiXDROLhISLQDRjVVAvawrAtLZWYK31bY7KlezPlQnl/D9Asxe85l
8jO5+0LdJ6VyOs/Hd4w52alDW/MFySDZSfQHMTIc30hLBJ8OnCEIvluVQQ2UQvoW
+no177N9L2Y+M9TcTA62ZyMXShHQGeh20rb4kK8f+iFX8NxtdHVSkxMEFSfDDyQ=
-----END CERTIFICATE-----`

// PIAWireGuardProvider mirrors NordVPNWireGuardProvider's retry-until-works
// design (see that type's doc comment for why: no server list can be
// trusted as "concurrency-safe" ahead of time, only a live handshake +
// real HTTP round trip proves it) but PIA's connection setup is
// structurally different from NordVPN's:
//
//   - NordVPN hands back an already-valid WireGuard private key from its
//     credentials API — nothing to register. PIA has no such endpoint:
//     each lease generates its own fresh X25519 keypair and registers the
//     public half with the chosen server via GET .../addKey, which
//     replies with that connection's peer IP, the server's own public
//     key, and its actual listen port (not a fixed 51820 the way NordVPN
//     always uses).
//   - addKey is served over HTTPS with a self-signed certificate — the
//     PIA client fleet's own tooling turns off verification for exactly
//     this call, not a shortcut invented here.
//   - PIA's DNS (10.0.0.243) and interface address (the peer_ip addKey
//     returns, not a fixed 10.5.0.2/32) differ from NordVPN's, and PIA is
//     IPv4-only (AllowedIPs has no ::/0).
//
// Everything downstream of "we have a live tunnel" — the netstack device,
// the local SOCKS5 bridge, the retry loop, the Lease bookkeeping keyed by
// Generation rather than workerID — is identical to
// NordVPNWireGuardProvider, so see that type for the reasoning.
type PIAWireGuardProvider struct {
	username, password string

	mu      sync.Mutex
	token   string
	servers []piaWGServer
	nextIdx int
	genCtr  int64
	live    map[int64]*wgTunnel
	// ranker: trí nhớ theo TỪNG server (khoá bằng ip, xem candidateID) về
	// thành công/thất bại thật — xem server_ranker.go doc comment. Trước
	// 2026-08-10, nextCandidate chỉ round-robin thuần, không nhớ gì.
	ranker *serverRanker
}

const (
	piaWGServerListURL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
	piaWGDNS           = "10.0.0.243"
)

// NewPIAWireGuardProvider fetches an auth token and the current WireGuard
// server list once. Returns an error if either fails.
func NewPIAWireGuardProvider(username, password string) (*PIAWireGuardProvider, error) {
	p := &PIAWireGuardProvider{username: username, password: password, live: map[int64]*wgTunnel{}, ranker: newServerRanker("pia-wg:" + username)}
	if err := p.fetchToken(); err != nil {
		return nil, fmt.Errorf("pia wireguard token: %w", err)
	}
	if err := p.refreshServers(); err != nil {
		return nil, fmt.Errorf("pia wireguard server list: %w", err)
	}
	return p, nil
}

func (p *PIAWireGuardProvider) Close() {
	p.mu.Lock()
	live := p.live
	p.live = map[int64]*wgTunnel{}
	p.mu.Unlock()
	for _, t := range live {
		t.socks.Close()
		t.dev.Close()
	}
}

// Same JSON request shape as PIAProvider.fetchToken (proven working
// against the real API) — PIA's WireGuard flow needs the raw token
// itself rather than the split username/password halves that provider
// derives from it, so this is a separate fetch, not shared state.
func (p *PIAWireGuardProvider) fetchToken() error {
	reqBody, _ := json.Marshal(map[string]string{
		"username": p.username,
		"password": p.password,
	})
	req, err := http.NewRequest("POST", piaTokenURL, strings.NewReader(string(reqBody)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.Token == "" {
		return fmt.Errorf("empty token in response")
	}
	p.mu.Lock()
	p.token = out.Token
	p.mu.Unlock()
	log.Printf("[PIA-WG] Token acquired for user: %s", p.username)
	return nil
}

// refreshServers parses PIA's server list response: a JSON document
// followed by a blank line and a PGP signature, not plain JSON — the
// signature isn't verified here (same trust boundary as every other
// plain-HTTP metadata fetch in this file; TLS already authenticates the
// connection to piaservers.net itself).
func (p *PIAWireGuardProvider) refreshServers() error {
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Get(piaWGServerListURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	text := strings.TrimSpace(string(raw))
	body := text
	if idx := strings.Index(text, "\n\n"); idx > 0 {
		body = text[:idx]
	}
	var data struct {
		Regions []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Servers struct {
				WG []struct {
					IP string `json:"ip"`
					CN string `json:"cn"`
				} `json:"wg"`
			} `json:"servers"`
		} `json:"regions"`
	}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return fmt.Errorf("cannot parse PIA server list: %w", err)
	}
	if len(data.Regions) == 0 {
		return fmt.Errorf("server list returned 0 regions")
	}
	var servers []piaWGServer
	for _, r := range data.Regions {
		for _, wg := range r.Servers.WG {
			servers = append(servers, piaWGServer{ip: wg.IP, cn: wg.CN, region: r.Name})
		}
	}
	if len(servers) == 0 {
		return fmt.Errorf("no wireguard servers in any region")
	}
	p.mu.Lock()
	p.servers = servers
	p.mu.Unlock()
	log.Printf("[PIA-WG] Loaded %d WireGuard servers across %d regions", len(servers), len(data.Regions))
	return nil
}

// nextCandidate thử server đã chứng minh đáng tin qua traffic thật trước
// (p.ranker.rankedGood, xem server_ranker.go), bỏ qua server đang trong
// cooldown sau lần fail gần nhất; hết server tốt thì rơi xuống round-robin
// bình thường, cũng bỏ qua cooldown trừ khi mọi server đều đang bị phạt
// (khi đó thà thử 1 server có thể hỏng còn hơn từ chối phục vụ hoàn toàn).
func (p *PIAWireGuardProvider) nextCandidate() (piaWGServer, error) {
	if len(p.servers) == 0 {
		return piaWGServer{}, fmt.Errorf("no PIA WireGuard servers loaded")
	}

	for _, id := range p.ranker.rankedGood() {
		if p.ranker.isPenalized(id) {
			continue
		}
		for _, s := range p.servers {
			if s.ip == id {
				return s, nil
			}
		}
	}

	for scanned := 0; scanned < len(p.servers); scanned++ {
		s := p.servers[p.nextIdx%len(p.servers)]
		p.nextIdx++
		if !p.ranker.isPenalized(s.ip) {
			return s, nil
		}
	}
	s := p.servers[p.nextIdx%len(p.servers)]
	p.nextIdx++
	return s, nil
}

// addKeyResponse is what PIA's per-server addKey endpoint returns for a
// freshly generated public key: this specific connection's assigned
// interface address, the server's own WireGuard public key, and the
// actual port to dial — none of these are fixed values the way NordVPN's
// are, so they have to come from here every time.
type addKeyResponse struct {
	Status     string `json:"status"`
	ServerKey  string `json:"server_key"`
	ServerIP   string `json:"server_ip"`
	ServerPort int    `json:"server_port"`
	PeerIP     string `json:"peer_ip"`
}

// piaCertPool is built once — parsing a fixed PEM constant can't fail at
// runtime in any way worth handling per-call.
var piaCertPool = func() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(piaCACert))
	return pool
}()

// addKey registers a fresh public key with one PIA server and returns
// that connection's assigned peer IP, the server's own WireGuard public
// key, and its real listen port.
//
// This mirrors PIA's own reference implementation
// (pia-foss/manual-connections, connect_to_wireguard_with_token.sh)
// exactly, after an earlier version of this call — modeled on a
// reverse-engineered tool instead — failed every single attempt with a
// bare TLS-level EOF. Three things the reference script does that the
// naive "GET https://<ip>/addKey" approach misses, all required together:
//
//  1. Port 1337, not 443. addKey is not served on the standard HTTPS
//     port at all.
//  2. The URL's host (and therefore the TLS SNI and Host header) must be
//     the server's certificate common name (cn from the server list),
//     not its bare IP — addKey's cert is issued for that hostname, and
//     PIA's edge presumably routes/validates on it. The actual TCP
//     socket still has to land on the real IP though (curl's
//     --connect-to does exactly this: keep the URL/SNI as the hostname,
//     redirect only where the socket connects) — DialContext below is
//     the Go equivalent.
//  3. The cert chains to PIA's own CA (piaCACert), not a public one and
//     not self-signed — verifying against it properly, instead of
//     turning verification off, is what the reference script does and
//     is not actually a self-signed-cert situation at all.
func (p *PIAWireGuardProvider) addKey(s piaWGServer, token, pubKeyB64 string) (*addKeyResponse, error) {
	if s.cn == "" {
		return nil, fmt.Errorf("server has no certificate common name (cn)")
	}
	u := fmt.Sprintf("https://%s:1337/addKey?pt=%s&pubkey=%s", s.cn, url.QueryEscape(token), url.QueryEscape(pubKeyB64))
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// The --connect-to equivalent: the request line/SNI above
				// still say s.cn:1337, but the socket actually connects here.
				return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, net.JoinHostPort(s.ip, "1337"))
			},
			TLSClientConfig: &tls.Config{RootCAs: piaCertPool},
		},
	}
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	var out addKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Status != "OK" {
		return nil, fmt.Errorf("addKey status=%q", out.Status)
	}
	return &out, nil
}

// tryOne attempts a full lease against one candidate: generate a fresh
// keypair, register it with the server, build the tunnel from what
// addKey hands back, wait briefly for a real handshake, then prove data
// actually flows with one real HTTP round trip — same verification
// NordVPNWireGuardProvider does and for the same reason (a completed
// handshake alone isn't proof the data path works).
func (p *PIAWireGuardProvider) tryOne(s piaWGServer, token string) (*wgTunnel, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())

	ak, err := p.addKey(s, token, pubB64)
	if err != nil {
		return nil, fmt.Errorf("addKey: %w", err)
	}

	peerAddr, err := netip.ParseAddr(ak.PeerIP)
	if err != nil {
		return nil, fmt.Errorf("bad peer_ip %q: %w", ak.PeerIP, err)
	}
	dnsAddr := netip.MustParseAddr(piaWGDNS)

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{peerAddr}, []netip.Addr{dnsAddr}, 1420)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))

	privHex := hex.EncodeToString(priv.Bytes())
	serverPubRaw, err := base64.StdEncoding.DecodeString(ak.ServerKey)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("bad server_key: %w", err)
	}
	serverPubHex := hex.EncodeToString(serverPubRaw)

	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s:%d\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		privHex, serverPubHex, ak.ServerIP, ak.ServerPort,
	)
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, fmt.Errorf("ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device up: %w", err)
	}

	handshakeOK := false
	deadline := time.Now().Add(wgHandshakeTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		info, err := dev.IpcGet()
		if err == nil && strings.Contains(info, "last_handshake_time_sec=") && !strings.Contains(info, "last_handshake_time_sec=0\n") {
			handshakeOK = true
			break
		}
	}
	if !handshakeOK {
		dev.Close()
		return nil, fmt.Errorf("no handshake within %s", wgHandshakeTimeout)
	}

	client := &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext}, Timeout: wgProbeTimeout}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("data path check failed: %w", err)
	}
	resp.Body.Close()

	socksSrv, err := newLocalSOCKS5Server(func(network, addr string) (net.Conn, error) {
		return tnet.DialContext(context.Background(), network, addr)
	})
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("local socks5 listener: %w", err)
	}

	return &wgTunnel{dev: dev, socks: socksSrv}, nil
}

func (p *PIAWireGuardProvider) acquireLease() (Lease, error) {
	p.mu.Lock()
	token := p.token
	p.mu.Unlock()
	if token == "" {
		return Lease{}, fmt.Errorf("no PIA token")
	}

	var lastErr error
	for attempt := 0; attempt < wgMaxAcquireAttempts; attempt++ {
		p.mu.Lock()
		s, err := p.nextCandidate()
		p.mu.Unlock()
		if err != nil {
			return Lease{}, err
		}
		t, err := p.tryOne(s, token)
		p.ranker.noteResult(s.ip, err == nil)
		if err != nil {
			lastErr = fmt.Errorf("%s (%s): %w", s.ip, s.region, err)
			continue
		}
		t.hostname = s.ip
		p.mu.Lock()
		p.genCtr++
		gen := p.genCtr
		p.live[gen] = t
		p.mu.Unlock()
		return Lease{URL: "socks5://" + t.socks.Addr(), AcquiredAt: time.Now(), Generation: gen}, nil
	}
	return Lease{}, fmt.Errorf("no working PIA WireGuard server after %d attempts (last: %v)", wgMaxAcquireAttempts, lastErr)
}

// Name identifies this source in MultiVPNProvider's per-provider stats
// (see multi_vpn_provider.go).
func (p *PIAWireGuardProvider) Name() string { return "PIA-WG" }

func (p *PIAWireGuardProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	if emit != nil {
		emit("Đang tìm server PIA (WireGuard) khả dụng…")
	}
	return p.acquireLease()
}

func (p *PIAWireGuardProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, kind FailureKind, emit func(string)) (Lease, error) {
	p.mu.Lock()
	t, ok := p.live[oldLease.Generation]
	p.mu.Unlock()
	if ok && t.hostname != "" {
		switch kind {
		case FailureBan:
			p.ranker.noteBan(t.hostname)
		case FailureNetwork:
			p.ranker.noteNetworkIssue(t.hostname)
		}
	}
	p.closeLease(oldLease.Generation)
	if emit != nil {
		emit("Đang đổi sang server PIA (WireGuard) khác…")
	}
	return p.acquireLease()
}

// NoteChunkOK implements networkHealthNotifier (see provider.go).
func (p *PIAWireGuardProvider) NoteChunkOK(lease Lease) {
	p.mu.Lock()
	t, ok := p.live[lease.Generation]
	p.mu.Unlock()
	if ok && t.hostname != "" {
		p.ranker.noteChunkOK(t.hostname)
	}
}

func (p *PIAWireGuardProvider) Release(workerID int, lease Lease) {
	p.closeLease(lease.Generation)
}

func (p *PIAWireGuardProvider) closeLease(gen int64) {
	p.mu.Lock()
	t, ok := p.live[gen]
	if ok {
		delete(p.live, gen)
	}
	p.mu.Unlock()
	if ok {
		t.socks.Close()
		t.dev.Close()
	}
}
