package webview2bridge

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type wgServer struct {
	hostname string
	station  string
	pubHex   string
	load     int
}

type wgTunnel struct {
	dev   *device.Device
	socks *localSOCKS5Server
}

const (
	wgHandshakeTimeout      = 3 * time.Second
	wgProbeTimeout          = 3 * time.Second
	wgMaxAcquireAttempts    = 6
	wgServerRefreshInterval = 30 * time.Minute

	// nordWGHandshakeTimeout/nordWGMaxAcquireAttempts: NordVPN-WireGuard's
	// own pool (thousands of servers) is an order of magnitude bigger than
	// PIA's (hundreds) or Surfshark's (~140 fixed hosts), so the same
	// 6-attempt ceiling under-uses the one thing it actually has going for
	// it — sheer candidate count. A tighter per-attempt timeout (2s
	// instead of 3s) keeps the worst case from actually getting slower
	// while trying more candidates: 10×2s=20s worst case vs. the shared
	// 6×3s=18s, for roughly 65% better odds of finding a working server
	// instead of exhausting attempts and forcing the caller to fall back
	// to a whole different provider (which starts the process over).
	nordWGHandshakeTimeout   = 2 * time.Second
	nordWGMaxAcquireAttempts = 10
)

// NordVPNWireGuardProvider hands out leases backed by real per-lease
// WireGuard tunnels to NordVPN's full server list (thousands of hosts,
// not just the ~12 dedicated SOCKS5 endpoints) — trading a heavier setup
// per lease (a real UDP handshake, not just a credential swap) for far
// more distinct exit IPs to rotate through over time.
//
// Empirically verified against the real API (2026-08-03): NordVPN's
// backend does not reliably keep more than one simultaneous WireGuard
// *data path* alive per account key — across several rounds of testing,
// most servers completed the handshake fine under concurrent load but
// silently stopped passing data for all but the most-recently-established
// session, with no error or teardown signal on the older ones. Exactly
// which servers behave differently isn't predictable from metadata
// (country, load, or whether they came from /v1/servers or the
// recommendations endpoint all produced a mix of hits and misses) — the
// only reliable signal is trying a real handshake AND a real HTTP round
// trip. So Acquire tries candidates one at a time (round-robin over the
// full list), verifying each for real before handing it out, and moves on
// immediately if one doesn't pan out rather than trying to remember which
// servers are "good" ahead of time.
//
// Each live tunnel exposes itself as a tiny local no-auth SOCKS5 server
// (see socks5_local_server.go) bound to 127.0.0.1 — the tunnel itself has
// no dialable network address (only a Go-level DialContext function from
// the userspace netstack), so this is what turns it into an ordinary
// socks5://127.0.0.1:<port> Lease.URL that LocalProxy's existing
// dialSOCKS5 path already knows how to use, unchanged.
//
// Built once at server startup and shared across every concurrent
// request, same reasoning as NordVPNProvider/PIAProvider — but unlike
// those, leases here ARE real per-caller resources (an open tunnel + a
// local listener), so Release/rotate must actually tear them down; kept
// in a map by Lease.Generation rather than workerID for the same reason
// those two providers avoid workerID: it repeats across concurrent
// requests once the provider is shared, so it can't be used as a key.
type NordVPNWireGuardProvider struct {
	privHex string

	mu      sync.Mutex
	servers []wgServer
	nextIdx int
	genCtr  int64
	live    map[int64]*wgTunnel

	refreshCancel context.CancelFunc
}

// NewNordVPNWireGuardProvider fetches the WireGuard private key and the
// current online server list once. Returns an error if either fails — a
// provider with no key or no servers can never build a working lease.
func NewNordVPNWireGuardProvider(token string) (*NordVPNWireGuardProvider, error) {
	privKeyB64, err := wgFetchPrivateKey(token)
	if err != nil {
		return nil, fmt.Errorf("nordvpn wireguard private key: %w", err)
	}
	privHex, err := wgKeyToHex(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("bad private key: %w", err)
	}
	p := &NordVPNWireGuardProvider{privHex: privHex, live: map[int64]*wgTunnel{}}
	if err := p.refreshServers(); err != nil {
		return nil, fmt.Errorf("nordvpn wireguard server list: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.refreshCancel = cancel
	go p.refreshLoop(ctx)

	return p, nil
}

// Close stops the background refresh loop and tears down every tunnel
// still open. Call once at server shutdown.
func (p *NordVPNWireGuardProvider) Close() {
	if p.refreshCancel != nil {
		p.refreshCancel()
	}
	p.mu.Lock()
	live := p.live
	p.live = map[int64]*wgTunnel{}
	p.mu.Unlock()
	for _, t := range live {
		t.socks.Close()
		t.dev.Close()
	}
}

func (p *NordVPNWireGuardProvider) refreshLoop(ctx context.Context) {
	t := time.NewTicker(wgServerRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.refreshServers(); err != nil {
				log.Printf("[NordVPN-WG] Warning: server list refresh failed: %v", err)
			}
		}
	}
}

func (p *NordVPNWireGuardProvider) refreshServers() error {
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Get("https://api.nordvpn.com/v1/servers?limit=0")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	var raw []struct {
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
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return err
	}
	var servers []wgServer
	for _, s := range raw {
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
		pubHex, err := wgKeyToHex(pubKey)
		if err != nil {
			continue
		}
		servers = append(servers, wgServer{hostname: s.Hostname, station: s.Station, pubHex: pubHex, load: s.Load})
	}
	if len(servers) == 0 {
		return fmt.Errorf("no online wireguard_udp servers found")
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].load < servers[j].load })

	p.mu.Lock()
	p.servers = servers
	p.mu.Unlock()
	log.Printf("[NordVPN-WG] Loaded %d online WireGuard servers", len(servers))
	return nil
}

// nextCandidate returns the next server in the round-robin. Caller must
// hold p.mu.
func (p *NordVPNWireGuardProvider) nextCandidate() (wgServer, error) {
	if len(p.servers) == 0 {
		return wgServer{}, fmt.Errorf("no NordVPN WireGuard servers loaded")
	}
	s := p.servers[p.nextIdx%len(p.servers)]
	p.nextIdx++
	return s, nil
}

// tryOne attempts a full lease against one candidate: build the tunnel,
// wait briefly for a real handshake, then prove data actually flows with
// one real HTTP round trip. The handshake alone isn't proof enough — see
// the type doc for why a completed handshake can still be a dead end.
func (p *NordVPNWireGuardProvider) tryOne(s wgServer) (*wgTunnel, error) {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.5.0.2")},
		[]netip.Addr{netip.MustParseAddr("103.86.96.100")},
		1420,
	)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s:51820\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		p.privHex, s.pubHex, s.station,
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
	deadline := time.Now().Add(nordWGHandshakeTimeout)
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
		return nil, fmt.Errorf("no handshake within %s", nordWGHandshakeTimeout)
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

// acquireLease tries candidates in round-robin order until one actually
// works, up to nordWGMaxAcquireAttempts (higher than the other two
// WireGuard providers — see that constant's doc comment for why) — see
// the type doc for why this can't be shortcut with a remembered "known
// good" list.
func (p *NordVPNWireGuardProvider) acquireLease() (Lease, error) {
	var lastErr error
	for attempt := 0; attempt < nordWGMaxAcquireAttempts; attempt++ {
		p.mu.Lock()
		s, err := p.nextCandidate()
		p.mu.Unlock()
		if err != nil {
			return Lease{}, err
		}
		t, err := p.tryOne(s)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", s.hostname, err)
			continue
		}
		p.mu.Lock()
		p.genCtr++
		gen := p.genCtr
		p.live[gen] = t
		p.mu.Unlock()
		return Lease{URL: "socks5://" + t.socks.Addr(), AcquiredAt: time.Now(), Generation: gen}, nil
	}
	return Lease{}, fmt.Errorf("no working NordVPN WireGuard server after %d attempts (last: %v)", nordWGMaxAcquireAttempts, lastErr)
}

func (p *NordVPNWireGuardProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	if emit != nil {
		emit("Đang tìm server NordVPN (WireGuard) khả dụng…")
	}
	return p.acquireLease()
}

func (p *NordVPNWireGuardProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	p.closeLease(oldLease.Generation)
	if emit != nil {
		emit("Đang đổi sang server NordVPN (WireGuard) khác…")
	}
	return p.acquireLease()
}

// Release tears down the actual tunnel and local listener this lease
// owns — unlike NordVPNProvider/PIAProvider, a WireGuard lease is a real
// resource, not just a credential string, so there is something to clean
// up here.
func (p *NordVPNWireGuardProvider) Release(workerID int, lease Lease) {
	p.closeLease(lease.Generation)
}

func (p *NordVPNWireGuardProvider) closeLease(gen int64) {
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

func wgKeyToHex(b64Key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func wgFetchPrivateKey(token string) (string, error) {
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
