package webview2bridge

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// IPVanishWireGuardProvider: each server has ITS OWN dedicated private key,
// unlike Surfshark's one-account-wide-key model. Two things were tried and
// ruled out first (2026-08-09, confirmed live against the real production
// VPS, not guessed):
//
//  1. A bulk dump of 3555 configs harvested all at once, each with its own
//     key - every single one failed to even complete a WireGuard handshake.
//     A freshly-registered key worked on the first try (same code, same
//     VPS), proving the CODE was never the problem - those 3555 keys were
//     already dead, almost certainly a per-account device/key cap tripped
//     by generating that many in one burst.
//  2. Registering ONE public key against many different servers (IPVanish's
//     "Custom Public Key" flow allows the API call to succeed for each),
//     hoping it would behave like Surfshark. It doesn't: re-registering the
//     same key against a new server silently invalidates its validity on
//     every PREVIOUS server. Testing 3 servers from such a batch - all
//     different from whichever was registered last - failed identically.
//
// The only model that has actually been confirmed to work: register keys
// the normal way (IPVanish's own "Generate for me" flow - no Custom Public
// Key involved, a few servers at a time, by hand, not thousands in a
// scripted burst), each server getting its own real dedicated key. Slower
// to grow, but every entry here is real and known-working rather than
// guessed at.
//
// ipvanish_servers.go embeds whatever pool has been hand-verified so far.
type IPVanishWireGuardProvider struct {
	mu      sync.Mutex
	nextIdx int
	genCtr  int64
	live    map[int64]*wgTunnel
	// ranker: trí nhớ theo TỪNG server (khoá bằng Host) — xem
	// server_ranker.go. Trước 2026-08-10, nextCandidate chỉ round-robin
	// thuần qua ipvanishServerList, không nhớ server nào vừa hỏng.
	ranker *serverRanker
}

type ipvanishServer struct {
	Name          string
	PrivateKeyB64 string
	Address       string // tunnel-assigned IP, no /32 suffix
	PublicKeyB64  string
	Host          string
	Port          string
}

const ipvanishDNS = "198.18.0.1"

// IPVanishServerCount exposes the embedded pool size for startup logging
// (main.go) without exporting the list itself.
func IPVanishServerCount() int { return len(ipvanishServerList) }

// NewIPVanishWireGuardProvider never fails on bad credentials the way
// NordVPN/PIA's token-exchange constructors can - there's no token, just
// the embedded list - so the only failure mode is the list being empty
// (would mean ipvanish_servers.go wasn't generated/is currently empty
// pending more hand-verified entries).
func NewIPVanishWireGuardProvider() (*IPVanishWireGuardProvider, error) {
	if len(ipvanishServerList) == 0 {
		return nil, fmt.Errorf("no ipvanish servers embedded (ipvanish_servers.go empty)")
	}
	return &IPVanishWireGuardProvider{live: map[int64]*wgTunnel{}, ranker: newServerRanker()}, nil
}

func (p *IPVanishWireGuardProvider) Close() {
	p.mu.Lock()
	live := p.live
	p.live = map[int64]*wgTunnel{}
	p.mu.Unlock()
	for _, t := range live {
		t.socks.Close()
		t.dev.Close()
	}
}

// nextCandidate thử server đã chứng minh đáng tin qua traffic thật trước
// (p.ranker.rankedGood, xem server_ranker.go), bỏ qua server đang cooldown
// sau lần fail gần nhất; hết server tốt thì rơi xuống round-robin bình
// thường qua ipvanishServerList như cũ.
func (p *IPVanishWireGuardProvider) nextCandidate() ipvanishServer {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, id := range p.ranker.rankedGood() {
		if p.ranker.isPenalized(id) {
			continue
		}
		for _, s := range ipvanishServerList {
			if s.Host == id {
				return s
			}
		}
	}

	for scanned := 0; scanned < len(ipvanishServerList); scanned++ {
		s := ipvanishServerList[p.nextIdx%len(ipvanishServerList)]
		p.nextIdx++
		if !p.ranker.isPenalized(s.Host) {
			return s
		}
	}
	s := ipvanishServerList[p.nextIdx%len(ipvanishServerList)]
	p.nextIdx++
	return s
}

// tryOne builds the tunnel from 1 candidate's own fully self-contained
// key/address/endpoint, then proves data actually flows with a real HTTP
// round trip - same verification every other WireGuard provider here does,
// for the same reason (a completed handshake alone doesn't prove the data
// path works).
func (p *IPVanishWireGuardProvider) tryOne(s ipvanishServer) (*wgTunnel, error) {
	privHex, err := wgKeyToHex(s.PrivateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("bad private key for %s: %w", s.Name, err)
	}
	pubHex, err := wgKeyToHex(s.PublicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("bad server pubkey for %s: %w", s.Name, err)
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(s.Address)},
		[]netip.Addr{netip.MustParseAddr(ipvanishDNS)},
		1420,
	)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))

	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s:%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		privHex, pubHex, s.Host, s.Port,
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

func (p *IPVanishWireGuardProvider) acquireLease() (Lease, error) {
	var lastErr error
	for attempt := 0; attempt < wgMaxAcquireAttempts; attempt++ {
		s := p.nextCandidate()
		t, err := p.tryOne(s)
		p.ranker.noteResult(s.Host, err == nil)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", s.Name, err)
			continue
		}
		p.mu.Lock()
		p.genCtr++
		gen := p.genCtr
		p.live[gen] = t
		p.mu.Unlock()
		return Lease{URL: "socks5://" + t.socks.Addr(), AcquiredAt: time.Now(), Generation: gen}, nil
	}
	return Lease{}, fmt.Errorf("no working IPVanish server after %d attempts (last: %v)", wgMaxAcquireAttempts, lastErr)
}

// Name identifies this source in MultiVPNProvider's per-provider stats
// (see multi_vpn_provider.go).
func (p *IPVanishWireGuardProvider) Name() string { return "IPVanish-WG" }

func (p *IPVanishWireGuardProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	if emit != nil {
		emit("Đang tìm server IPVanish khả dụng…")
	}
	return p.acquireLease()
}

func (p *IPVanishWireGuardProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	p.closeLease(oldLease.Generation)
	if emit != nil {
		emit("Đang đổi sang server IPVanish khác…")
	}
	return p.acquireLease()
}

func (p *IPVanishWireGuardProvider) Release(workerID int, lease Lease) {
	p.closeLease(lease.Generation)
}

func (p *IPVanishWireGuardProvider) closeLease(gen int64) {
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
