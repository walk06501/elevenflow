package webview2bridge

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
// only a live handshake + real HTTP round trip proves it), but differs
// from both NordVPN and PIA in its key lifecycle:
//
//   - REWRITTEN 2026-08-12 (see login/registerKey below): an earlier
//     version used ONE static private key for the provider's entire
//     lifetime, taken directly from the account (the same key the
//     Surfshark app itself uses) with no API call involved at all. That
//     was wrong — reading Surfshark's own real client implementations
//     (e.g. github.com/yazdan/openwrt-surfshark-wireguard's
//     gen_wg_config.bash) showed Surfshark's WireGuard keys are NOT
//     fire-and-forget: a key only works once registered via
//     POST /v1/account/users/public-keys using a JWT from
//     POST /v1/auth/login, and that registration has its own expiresAt —
//     structurally the same "register a fresh key per session" contract
//     PIA's addKey uses (see PIAWireGuardProvider), just with a
//     login+register call pair instead of PIA's single addKey. A single
//     long-lived static key with no renewal logic explains the sustained
//     0% success rate seen 2026-08-10 far better than anything server-side:
//     the account's one hardcoded key's registration had every opportunity
//     to have quietly expired or been superseded (e.g. by the Surfshark
//     app itself re-registering a new key later) with nothing in this
//     codebase able to notice or recover.
//   - Now generates a fresh X25519 keypair and registers it PER LEASE,
//     exactly like PIA — the fix for the same underlying reason PIA
//     already works this way: never depending on a key's registration
//     still being valid days or weeks later.
//   - Still no server-list API for the SERVER side (see surfsharkServerList
//     in surfshark_servers.go) — Surfshark does publish one
//     (api.surfshark.com/v4/server/clusters/, confirmed live 2026-08-12,
//     and its pubKey values matched every embedded entry checked), but
//     switching to it is a separate, lower-priority improvement from the
//     key-lifecycle bug this rewrite actually fixes; the embedded list
//     was NOT the problem (its keys are the SERVERS' own long-lived
//     identity keys, unrelated to the CLIENT key rewritten here).
//   - Interface address and DNS (surfsharkAddress/surfsharkDNS below)
//     stay fixed regardless of which key is registered — unlike PIA's
//     addKey, Surfshark's registration response carries no per-key peer
//     IP assignment (confirmed from the same reference script), so every
//     registered key uses this same client-side address.
type SurfsharkWireGuardProvider struct {
	username, password string

	mu      sync.Mutex
	token   string
	nextIdx int
	genCtr  int64
	live    map[int64]*wgTunnel
	// loginMu serializes RE-login specifically (see reloginIfStillStale) —
	// separate from mu, which only ever guards short field reads/writes.
	// Without this, N concurrent registerKey calls all seeing the same
	// expired token would each fire their own POST /v1/auth/login at once;
	// harmless to correctness (last write wins, p.mu still protects the
	// field) but wasteful and looks like credential-stuffing-shaped traffic
	// from Surfshark's side for no benefit — one relogin already fixes it
	// for everyone waiting.
	loginMu sync.Mutex
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
	surfsharkAddress  = "10.14.0.2"
	surfsharkDNS      = "162.252.172.57"
	surfsharkPort     = "51820"
	surfsharkLoginURL = "https://api.surfshark.com/v1/auth/login"
	surfsharkKeyURL   = "https://api.surfshark.com/v1/account/users/public-keys"
)

// NewSurfsharkWireGuardProvider takes the account's real login
// username/password (the same credentials the Surfshark app itself signs
// in with) rather than a raw private key — see the type doc comment for
// why: a key only works after being registered through this same login,
// and that registration expires, so there is no long-lived static secret
// to hand in directly anymore. Fails fast if login itself fails, same
// reasoning as PIA/NordVPN: a credential that can't authenticate now will
// never serve a request later either.
func NewSurfsharkWireGuardProvider(username, password string) (*SurfsharkWireGuardProvider, error) {
	if len(surfsharkServerList) == 0 {
		return nil, fmt.Errorf("no surfshark servers configured")
	}
	p := &SurfsharkWireGuardProvider{username: username, password: password, live: map[int64]*wgTunnel{}, ranker: newServerRanker()}
	if err := p.login(); err != nil {
		return nil, fmt.Errorf("surfshark login: %w", err)
	}
	return p, nil
}

// login exchanges username/password for a JWT bearer token used to
// register keys (registerKey). Same request shape as
// github.com/yazdan/openwrt-surfshark-wireguard's wg_login, confirmed
// against the real endpoint 2026-08-12.
func (p *SurfsharkWireGuardProvider) login() error {
	reqBody, _ := json.Marshal(map[string]string{"username": p.username, "password": p.password})
	req, err := http.NewRequest("POST", surfsharkLoginURL, strings.NewReader(string(reqBody)))
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
	log.Printf("[Surfshark-WG] Login OK for user: %s", p.username)
	return nil
}

// reloginIfStillStale re-authenticates only if the token is STILL whatever
// staleToken was when the caller decided to relogin — if another goroutine
// already refreshed it in the meantime (a real possibility: many concurrent
// registerKey calls can all observe the same expired token at once), this
// is a no-op and the caller just picks up the already-fresh token. loginMu
// (not p.mu) serializes this check-then-act across goroutines so at most
// one real HTTP login happens per actual expiry, not one per caller that
// noticed.
func (p *SurfsharkWireGuardProvider) reloginIfStillStale(staleToken string) error {
	p.loginMu.Lock()
	defer p.loginMu.Unlock()
	p.mu.Lock()
	current := p.token
	p.mu.Unlock()
	if current != staleToken {
		return nil // someone else already refreshed it while we waited for loginMu
	}
	return p.login()
}

// registerKey activates one freshly generated public key so Surfshark's
// servers will complete a handshake against it — an unregistered key
// handshakes with nobody (silently, same failure shape as an expired
// registration), so this must succeed before tryOne attempts a tunnel.
// On a 401 (token expired — the same signal
// github.com/yazdan/openwrt-surfshark-wireguard's wg_reg_pubkey checks
// for), re-logs in (deduplicated across concurrent callers — see
// reloginIfStillStale) and retries exactly once, mirroring that reference
// script's own retry-after-relogin behavior.
func (p *SurfsharkWireGuardProvider) registerKey(pubKeyB64 string) error {
	for attempt := 0; attempt < 2; attempt++ {
		p.mu.Lock()
		token := p.token
		p.mu.Unlock()

		reqBody, _ := json.Marshal(map[string]string{"pubKey": pubKeyB64})
		req, err := http.NewRequest("POST", surfsharkKeyURL, strings.NewReader(string(reqBody)))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			if err := p.reloginIfStillStale(token); err != nil {
				return fmt.Errorf("token expired, re-login failed: %w", err)
			}
			continue
		}
		// 200/201/202 all seen as success shapes across Surfshark's own
		// client tooling (yazdan's script accepts the same range) — not
		// just 200, so match that instead of a single exact code.
		if resp.StatusCode < 200 || resp.StatusCode > 202 {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
		}
		return nil
	}
	return fmt.Errorf("registerKey: exhausted retries")
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

// tryOne generates a fresh keypair and registers it (registerKey — see the
// type doc comment for why a key must be freshly registered, not reused),
// resolves the candidate hostname, builds the tunnel, waits briefly for a
// real handshake, then proves data actually flows with one real HTTP round
// trip — same verification the other two WireGuard providers do and for
// the same reason (a completed handshake alone isn't proof the data path
// works).
func (p *SurfsharkWireGuardProvider) tryOne(host, pubKeyB64 string) (*wgTunnel, error) {
	curve := ecdh.X25519()
	myPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	myPubB64 := base64.StdEncoding.EncodeToString(myPriv.PublicKey().Bytes())
	if err := p.registerKey(myPubB64); err != nil {
		return nil, fmt.Errorf("register key: %w", err)
	}
	myPrivHex := hex.EncodeToString(myPriv.Bytes())

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
		myPrivHex, pubHex, ip, surfsharkPort,
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
