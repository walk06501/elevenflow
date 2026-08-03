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
//   - No token exchange, no per-connection registration like PIA's
//     addKey — Surfshark's WireGuard private key comes directly from the
//     account (the same key the Surfshark app itself would use), fixed
//     for the life of this provider.
//   - No server-list API at all. Surfshark doesn't publish one the way
//     NordVPN/PIA do, so the hostname + server public key pairs in
//     surfshark_servers.go are a fixed, embedded list. Each hostname's IP
//     is resolved via plain DNS at lease time (not cached at startup),
//     since Surfshark load-balances behind DNS and a stale cached IP
//     would defeat that.
//   - Its own fixed interface address and DNS (see surfsharkAddress/
//     surfsharkDNS below) — these are Surfshark-specific, not NordVPN's;
//     an earlier version of this file guessed NordVPN's values instead,
//     which let the handshake complete but silently dropped all data.
type SurfsharkWireGuardProvider struct {
	privHex string

	mu      sync.Mutex
	nextIdx int
	genCtr  int64
	live    map[int64]*wgTunnel
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
// key directly (base64, same form the Surfshark app itself uses) — there
// is no API call that could fail the way NordVPN/PIA's credential fetch
// can, so this only fails on a malformed key.
func NewSurfsharkWireGuardProvider(privateKeyB64 string) (*SurfsharkWireGuardProvider, error) {
	privHex, err := wgKeyToHex(privateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("bad surfshark private key: %w", err)
	}
	if len(surfsharkServerList) == 0 {
		return nil, fmt.Errorf("no surfshark servers configured")
	}
	return &SurfsharkWireGuardProvider{privHex: privHex, live: map[int64]*wgTunnel{}}, nil
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

func (p *SurfsharkWireGuardProvider) nextCandidate() struct {
	Host   string
	PubKey string
} {
	p.mu.Lock()
	defer p.mu.Unlock()
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
