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

// SurfsharkWireGuardProvider mirrors NordVPNWireGuardProvider's
// retry-until-works design (see that type's doc comment for the full
// reasoning — no server can be trusted as "will work" ahead of time,
// only a live handshake + real HTTP round trip proves it), but its setup
// is the simplest of the three:
//
//   - No per-connection registration like PIA's addKey at LEASE time —
//     one WireGuard private key, provided directly, fixed for the life of
//     this provider.
//   - No server-list API used for the SERVER side — the hostname + server
//     public key pairs in surfshark_servers.go are a fixed, embedded
//     list (Surfshark does publish one, api.surfshark.com/v4/server/clusters/,
//     confirmed live 2026-08-12 with pubKey values matching every embedded
//     entry checked, but nothing here currently uses it). Each hostname's
//     IP is resolved via plain DNS at lease time (not cached at startup),
//     since Surfshark load-balances behind DNS.
//   - Its own fixed interface address and DNS (see surfsharkAddress/
//     surfsharkDNS below) — these are Surfshark-specific, not NordVPN's;
//     an earlier version of this file guessed NordVPN's values instead,
//     which let the handshake complete but silently dropped all data.
//
// HISTORY (2026-08-12): briefly rewritten to generate a fresh key and
// register it per lease via POST /v1/auth/login + POST
// /v1/account/users/public-keys, matching how Surfshark's own real client
// tools (github.com/yazdan/openwrt-surfshark-wireguard, github.com/Eryk-J/
// surfshark-wg, and others) work, on the theory that the account's one
// static key's registration had quietly expired (explaining the sustained
// 0% seen since 2026-08-10). That theory may still be right, but the fix
// was reverted: Surfshark's auth API sits behind Cloudflare Bot Management,
// confirmed (2026-08-12) to return 403 for a plain HTTP client — curl, this
// codebase's net/http, and by extension every one of those reference
// scripts too — REGARDLESS of source IP (tested from this VPS, a second
// unrelated VPS, and a residential machine, all blocked identically; even
// a realistic browser User-Agent didn't help, and the response carries
// Cloudflare's __cf_bm bot-management cookie, which is TLS/JA3-fingerprint
// based, not header-based). The only real client tooling found that gets
// past this (github.com/MSalman5230/surfshark-wireguard-config-generator)
// does so with Selenium driving an actual browser, seeded with cookies
// from a real prior human login — i.e. there is no login/registration path
// available to a plain Go HTTP client at all right now, only to a genuine
// browser session. Routing through this codebase's own WebView2 browser
// automation would work but is a real engineering project or its own,
// not justified for a source that only ever carries a small weight in the
// pool — so back to a human periodically extracting a fresh private key
// via a real browser (Surfshark app or my.surfshark.com's manual-setup
// page) and handing it in directly, same as before 2026-08-12.
type SurfsharkWireGuardProvider struct {
	privHex string

	mu      sync.Mutex
	nextIdx int
	genCtr  int64
	live    map[int64]*wgTunnel
	// ranker: trí nhớ theo TỪNG server (khoá bằng Host) — xem
	// server_ranker.go. Trước 2026-08-10, nextCandidate chỉ round-robin
	// thuần qua surfsharkServerList, không nhớ server nào vừa hỏng.
	ranker *serverRanker
}

// surfsharkAddress/surfsharkDNS match a real config downloaded from
// Surfshark's own site (MSalman5230/surfshark-wireguard-config-generator's
// wireguard-configs/*.conf) verbatim — an earlier version of this file
// guessed NordVPN's values (10.5.0.2, 103.86.96.100) instead, which was
// wrong: the WireGuard handshake still completed (it doesn't care about
// inner IPs), but no data ever passed, almost certainly because
// Surfshark's server only recognizes 10.14.0.2 as this key's assigned
// address and silently drops packets claiming to be from anything else.
const (
	surfsharkAddress = "10.14.0.2"
	surfsharkDNS     = "162.252.172.57"
	surfsharkPort    = "51820"
)

// NewSurfsharkWireGuardProvider takes the account's own WireGuard private
// key directly (base64, extracted via a real browser session — see the
// type doc comment for why this has to be a human-provided key rather
// than something this codebase can log in and register itself) — there
// is no API call that could fail the way NordVPN/PIA's credential fetch
// can, so this only fails on a malformed key. Whoever supplies the key is
// responsible for refreshing it (via the admin panel) if it ever stops
// working — nothing here can detect or renew an expired registration on
// its own, since doing so would need the same Cloudflare-blocked API.
func NewSurfsharkWireGuardProvider(privateKeyB64 string) (*SurfsharkWireGuardProvider, error) {
	privHex, err := wgKeyToHex(privateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("bad surfshark private key: %w", err)
	}
	if len(surfsharkServerList) == 0 {
		return nil, fmt.Errorf("no surfshark servers configured")
	}
	return &SurfsharkWireGuardProvider{privHex: privHex, live: map[int64]*wgTunnel{}, ranker: newServerRanker()}, nil
}

func (p *SurfsharkWireGuardProvider) Close() {
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
// thường qua surfsharkServerList như cũ.
func (p *SurfsharkWireGuardProvider) nextCandidate() struct {
	Host   string
	PubKey string
} {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, id := range p.ranker.rankedGood() {
		if p.ranker.isPenalized(id) {
			continue
		}
		for _, s := range surfsharkServerList {
			if s.Host == id {
				return s
			}
		}
	}

	for scanned := 0; scanned < len(surfsharkServerList); scanned++ {
		s := surfsharkServerList[p.nextIdx%len(surfsharkServerList)]
		p.nextIdx++
		if !p.ranker.isPenalized(s.Host) {
			return s
		}
	}
	s := surfsharkServerList[p.nextIdx%len(surfsharkServerList)]
	p.nextIdx++
	return s
}

// tryOne resolves the candidate hostname, builds the tunnel, waits
// briefly for a real handshake, then proves data actually flows with one
// real HTTP round trip — same verification the other two WireGuard
// providers do and for the same reason (a completed handshake alone
// isn't proof the data path works).
func (p *SurfsharkWireGuardProvider) tryOne(host, pubKeyB64 string) (*wgTunnel, error) {
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	ip := ips[0]

	pubHex, err := wgKeyToHex(pubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("bad server pubkey: %w", err)
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(surfsharkAddress)},
		[]netip.Addr{netip.MustParseAddr(surfsharkDNS)},
		1420,
	)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))

	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s:%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		p.privHex, pubHex, ip, surfsharkPort,
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

func (p *SurfsharkWireGuardProvider) acquireLease() (Lease, error) {
	var lastErr error
	for attempt := 0; attempt < wgMaxAcquireAttempts; attempt++ {
		s := p.nextCandidate()
		t, err := p.tryOne(s.Host, s.PubKey)
		p.ranker.noteResult(s.Host, err == nil)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", s.Host, err)
			continue
		}
		p.mu.Lock()
		p.genCtr++
		gen := p.genCtr
		p.live[gen] = t
		p.mu.Unlock()
		return Lease{URL: "socks5://" + t.socks.Addr(), AcquiredAt: time.Now(), Generation: gen}, nil
	}
	return Lease{}, fmt.Errorf("no working Surfshark server after %d attempts (last: %v)", wgMaxAcquireAttempts, lastErr)
}

// Name identifies this source in MultiVPNProvider's per-provider stats
// (see multi_vpn_provider.go).
func (p *SurfsharkWireGuardProvider) Name() string { return "Surfshark-WG" }

func (p *SurfsharkWireGuardProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	if emit != nil {
		emit("Đang tìm server Surfshark khả dụng…")
	}
	return p.acquireLease()
}

func (p *SurfsharkWireGuardProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	p.closeLease(oldLease.Generation)
	if emit != nil {
		emit("Đang đổi sang server Surfshark khác…")
	}
	return p.acquireLease()
}

func (p *SurfsharkWireGuardProvider) Release(workerID int, lease Lease) {
	p.closeLease(lease.Generation)
}

func (p *SurfsharkWireGuardProvider) closeLease(gen int64) {
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
