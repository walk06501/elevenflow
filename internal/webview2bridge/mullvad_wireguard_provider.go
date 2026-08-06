package webview2bridge

import (
	"context"
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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// MullvadWireGuardProvider: same "verify real handshake + real HTTP round
// trip before trusting a tunnel" shape as the other WireGuard providers,
// but a genuinely different provisioning model from all four of them —
// confirmed by reading Mullvad's own official github.com/mullvad/mullvad-wg.sh
// and by a real end-to-end test against a real account (2026-08-06:
// POST /wg -> HTTP 201, real IP assigned; tunnel to nl-ams-wg-001 completed
// a real handshake and a real HTTP round trip through it):
//
//  1. Auth is a bare account NUMBER, no username/password/2FA/SRP.
//  2. The account is capped at 5 REGISTERED WireGuard public keys total
//     (Mullvad's own hard limit, confirmed via web search — registering a
//     6th is expected to fail). Unlike Proton/Surfshark's "one key, many
//     servers, unlimited concurrent data paths" model, Mullvad additionally
//     will NOT let the SAME key carry two simultaneous sessions: WireGuard
//     servers key their peer table by public key, so two concurrent
//     endpoints presenting the same key stomp on each other's table entry
//     (confirmed via web search, matches WireGuard's own documented
//     behavior, not Mullvad-specific). So: register up to mullvadMaxKeys
//     keys ONCE at startup (persisted for the provider's lifetime, not
//     regenerated per lease), and treat "a free key" as the hard
//     concurrency resource — same fail-fast-when-exhausted reasoning as
//     NordVPNWireGuardProvider's slots channel (see that file's doc
//     comment), implemented here as a linear scan over keys[].inUse instead
//     of a channel since the resource being limited (a specific pre-
//     registered key) needs to be handed back to the SAME caller's release,
//     not just counted. Capacity is whatever registration actually
//     succeeded (<= 5), since a re-run against an account that already has
//     some devices registered elsewhere may get fewer.
//  3. Server list: GET /app/v1/relays (public, no auth) — same
//     one-endpoint-picked-per-lease model as the other three, round-robin
//     across every "active" relay.
//
// NOT YET MEASURED: whether Mullvad's own infra tolerates the same kind of
// concurrent-handshake-storm NordVPN's did not (see that file's
// probeRound) — this provider intentionally does NOT fan out multiple
// simultaneous probe attempts per acquire, both because the 5-key cap
// makes "burn several keys probing at once" expensive (each probe attempt
// occupies a whole key-slot for its duration) and because no community
// project reviewed while building this one ever tries concurrent handshakes
// against the same account. Revisit with cmd/testconcurrency if real
// traffic shows this provider timing out under load the other three do not.
type MullvadWireGuardProvider struct {
	httpClient *http.Client
	account    string

	mu      sync.Mutex
	keys    []mullvadKey
	servers []mullvadServer
	nextIdx int
	genCtr  int64
	live    map[int64]*wgTunnel

	// liveKey: which key index (into p.keys) backs each live lease
	// generation, so closeLease can free the exact key it checked out —
	// separate lock from mu purely so a slow tunnel teardown never blocks
	// nextServer()/checkoutKey() for unrelated in-flight acquires.
	liveKeyMu sync.Mutex
	liveKey   map[int64]int
}

type mullvadKey struct {
	privHex   string
	assignedV4 string // e.g. "10.71.231.179" (no /32 — embedded directly in the tunnel's own address)
	inUse     bool
}

type mullvadServer struct {
	hostname string
	entryIP  string
	pubHex   string
}

// mullvadKeysPath: a cwd-relative path (NOT %LOCALAPPDATA%/os.UserConfigDir())
// deliberately — this server runs both as a SYSTEM-context Scheduled Task in
// production and as a plain interactive process during manual debugging
// (both launch with WorkingDirectory/cwd pinned to the install dir, e.g.
// C:\elevenflow — see setup-eleven-vps.ps1), and those two contexts resolve
// %LOCALAPPDATA% to two DIFFERENT paths. A per-user path here would mean a
// manual debug run can never see keys a Scheduled Task run persisted (or
// vice versa) and would just re-register a fresh batch every time — the
// exact bug this file exists to fix. One file per account number, since the
// portal can configure more than one Mullvad account.
func mullvadKeysPath(account string) string {
	return filepath.Join(".", fmt.Sprintf("mullvad_keys_%s.json", account))
}

type mullvadPersistedKey struct {
	PrivHex    string `json:"priv_hex"`
	AssignedV4 string `json:"assigned_v4"`
}

// loadMullvadKeys reads a previously-saved key set. A missing file (first
// run ever for this account) is not an error — returns nil, nil so the
// caller registers a fresh batch exactly like before this fix existed.
func loadMullvadKeys(account string) ([]mullvadKey, error) {
	data, err := os.ReadFile(mullvadKeysPath(account))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var saved []mullvadPersistedKey
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("parse %s: %w", mullvadKeysPath(account), err)
	}
	keys := make([]mullvadKey, 0, len(saved))
	for _, s := range saved {
		if s.PrivHex == "" || s.AssignedV4 == "" {
			continue
		}
		keys = append(keys, mullvadKey{privHex: s.PrivHex, assignedV4: s.AssignedV4})
	}
	return keys, nil
}

// saveMullvadKeys persists the full current key set, overwriting whatever
// was there before — called once after NewMullvadWireGuardProvider settles
// on its final key list (loaded + any newly registered), so the NEXT
// restart reuses every key this run has rather than only the newest batch.
func saveMullvadKeys(account string, keys []mullvadKey) error {
	saved := make([]mullvadPersistedKey, len(keys))
	for i, k := range keys {
		saved[i] = mullvadPersistedKey{PrivHex: k.privHex, AssignedV4: k.assignedV4}
	}
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(mullvadKeysPath(account), data, 0o600)
}

const (
	mullvadAPIBase = "https://api.mullvad.net"
	mullvadDNS     = "10.64.0.1" // wireguard.ipv4_gateway from /app/v1/relays, stable Mullvad-side constant
	mullvadPort    = "51820"
	mullvadMaxKeys = 5 // Mullvad's own hard per-account device cap
)

// NewMullvadWireGuardProvider loads any WireGuard keys this account already
// has saved locally (mullvadKeysPath) and reuses them as-is — NO API call at
// all for keys already on disk, since they're already registered on
// Mullvad's side from a previous run. Only tops up with freshly-registered
// keys if the saved set has fewer than mullvadMaxKeys (first-ever run, or
// an account that started with some slots already free). This is the fix
// for a real bug found 2026-08-06: the original version generated and
// registered mullvadMaxKeys BRAND NEW keys on every single process restart
// with no persistence at all, silently orphaning the previous run's keys —
// each one still occupying a device slot on Mullvad's side with its private
// key gone forever — and burning through the account's hard 5-device cap
// within 3-4 restarts (confirmed live: 3 manual restarts in one evening
// left 4 of 5 slots permanently consumed by keys nothing could ever use
// again). Returns an error only if there are no usable keys at all AFTER
// both loading and topping up.
func NewMullvadWireGuardProvider(accountNumber string) (*MullvadWireGuardProvider, error) {
	p := &MullvadWireGuardProvider{
		httpClient: &http.Client{Timeout: 20 * time.Second},
		account:    accountNumber,
		live:       map[int64]*wgTunnel{},
		liveKey:    map[int64]int{},
	}

	loaded, err := loadMullvadKeys(accountNumber)
	if err != nil {
		log.Printf("[mullvad] could not read saved keys (%v), registering fresh instead", err)
	} else if len(loaded) > 0 {
		p.keys = append(p.keys, loaded...)
		log.Printf("[mullvad] reusing %d previously-registered key(s) from %s", len(loaded), mullvadKeysPath(accountNumber))
	}

	var lastKeyErr error
	registeredNew := 0
	for len(p.keys) < mullvadMaxKeys {
		k, err := p.registerNewKey()
		if err != nil {
			lastKeyErr = err
			log.Printf("[mullvad] key %d/%d registration failed: %v", len(p.keys)+1, mullvadMaxKeys, err)
			break // a failed registration this run won't succeed on the next attempt either (throttle/cap) — stop, don't waste more requests
		}
		p.keys = append(p.keys, k)
		registeredNew++
	}
	if len(p.keys) == 0 {
		return nil, fmt.Errorf("mullvad: no usable WireGuard key (last registration error: %w)", lastKeyErr)
	}
	if registeredNew > 0 {
		if err := saveMullvadKeys(accountNumber, p.keys); err != nil {
			// Not fatal — the newly registered keys still work for THIS run,
			// just won't survive to the next restart. Logged loudly since
			// silently reverting to the old bug's behavior is exactly the
			// failure mode this fix exists to prevent.
			log.Printf("[mullvad] WARNING: could not save keys to %s (%v) — next restart will register fresh keys again and may hit the device cap", mullvadKeysPath(accountNumber), err)
		}
	}

	if err := p.refreshServers(); err != nil {
		return nil, fmt.Errorf("mullvad server list: %w", err)
	}

	log.Printf("[mullvad] %d/%d key(s) ready (%d reused, %d newly registered), %d relay(s) loaded",
		len(p.keys), mullvadMaxKeys, len(p.keys)-registeredNew, registeredNew, len(p.servers))
	return p, nil
}

// KeyCount returns how many WireGuard keys were actually registered
// (<= mullvadMaxKeys — see NewMullvadWireGuardProvider doc comment on why
// this can be fewer than 5). This is the provider's real concurrency
// ceiling, so callers (main.go) use it as the round-robin weight instead of
// a fixed per-provider constant like the other four providers use, since
// unlike them Mullvad's usable concurrency isn't a flat number picked from
// measurement — it's whatever registration actually succeeded.
func (p *MullvadWireGuardProvider) KeyCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.keys)
}

func (p *MullvadWireGuardProvider) Close() {
	p.mu.Lock()
	live := p.live
	p.live = map[int64]*wgTunnel{}
	p.mu.Unlock()
	for _, t := range live {
		t.socks.Close()
		t.dev.Close()
	}
}

// ── Key registration (POST /wg) ───────────────────────────────────────────

// registerNewKey generates a fresh X25519 keypair locally and registers its
// public key against the account via POST /wg. Response body on success is
// literally "<ipv4>/32,<ipv6>/128" (plain text, not JSON) — confirmed live
// 2026-08-06 ("10.71.231.179/32,fc00:bbbb:bbbb:bb01::8:e7b2/128").
//
// account and pubkey MUST go through --data-urlencode equivalent (url.Values
// here does this automatically): the base64 pubkey routinely contains '+',
// which application/x-www-form-urlencoded silently reinterprets as a space
// if sent raw — confirmed live the hard way (first attempt: HTTP 400
// "Invalid public key" with a correctly-generated key, second attempt with
// proper encoding: HTTP 201).
func (p *MullvadWireGuardProvider) registerNewKey() (mullvadKey, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return mullvadKey{}, fmt.Errorf("generate key: %w", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return mullvadKey{}, fmt.Errorf("derive pubkey: %w", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	form := url.Values{}
	form.Set("account", p.account)
	form.Set("pubkey", pubB64)

	req, err := http.NewRequest(http.MethodPost, mullvadAPIBase+"/wg", strings.NewReader(form.Encode()))
	if err != nil {
		return mullvadKey{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return mullvadKey{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return mullvadKey{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	// "<ipv4>/32,<ipv6>/128" — only the IPv4 half is used (matches the other
	// three WireGuard providers here, which are all IPv4-only tunnels).
	v4Part := strings.SplitN(string(body), ",", 2)[0]
	v4 := strings.SplitN(v4Part, "/", 2)[0]
	if net.ParseIP(v4) == nil {
		return mullvadKey{}, fmt.Errorf("unexpected /wg response, no parseable IPv4: %s", truncate(string(body), 200))
	}

	return mullvadKey{privHex: hex.EncodeToString(priv[:]), assignedV4: v4}, nil
}

// ── Server list (GET /app/v1/relays, public) ──────────────────────────────

type mullvadRelaysResp struct {
	Wireguard struct {
		Relays []struct {
			Hostname  string `json:"hostname"`
			Active    bool   `json:"active"`
			IPv4AddrIn string `json:"ipv4_addr_in"`
			PublicKey string `json:"public_key"`
		} `json:"relays"`
	} `json:"wireguard"`
}

func (p *MullvadWireGuardProvider) refreshServers() error {
	resp, err := p.httpClient.Get(mullvadAPIBase + "/app/v1/relays")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var data mullvadRelaysResp
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("decode relays: %w", err)
	}

	var servers []mullvadServer
	for _, r := range data.Wireguard.Relays {
		if !r.Active || r.IPv4AddrIn == "" || r.PublicKey == "" {
			continue
		}
		pubHex, err := wgKeyToHex(r.PublicKey)
		if err != nil {
			continue
		}
		servers = append(servers, mullvadServer{hostname: r.Hostname, entryIP: r.IPv4AddrIn, pubHex: pubHex})
	}
	if len(servers) == 0 {
		return fmt.Errorf("no active relays in /app/v1/relays response")
	}

	p.mu.Lock()
	p.servers = servers
	p.mu.Unlock()
	return nil
}

func (p *MullvadWireGuardProvider) nextServer() (mullvadServer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.servers) == 0 {
		return mullvadServer{}, fmt.Errorf("no Mullvad relays loaded")
	}
	s := p.servers[p.nextIdx%len(p.servers)]
	p.nextIdx++
	return s, nil
}

// checkoutKey claims a free key from the pool (fails if every key is
// already checked out by a live tunnel — see slots). Returns the key's
// INDEX (stable, into p.keys) so releaseKey can free the exact same one.
func (p *MullvadWireGuardProvider) checkoutKey() (idx int, k mullvadKey, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.keys {
		if !p.keys[i].inUse {
			p.keys[i].inUse = true
			return i, p.keys[i], nil
		}
	}
	return -1, mullvadKey{}, fmt.Errorf("no free Mullvad key")
}

func (p *MullvadWireGuardProvider) releaseKey(idx int) {
	if idx < 0 {
		return
	}
	p.mu.Lock()
	if idx < len(p.keys) {
		p.keys[idx].inUse = false
	}
	p.mu.Unlock()
}

// ── Tunnel (mirrors ProtonVPNWireGuardProvider.tryOne — real handshake,
// then one real HTTP round trip, since a completed handshake alone is not
// proof the data path actually carries traffic) ───────────────────────────

func (p *MullvadWireGuardProvider) tryOne(k mullvadKey, s mullvadServer) (*wgTunnel, error) {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(k.assignedV4)},
		[]netip.Addr{netip.MustParseAddr(mullvadDNS)},
		1420,
	)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))

	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s:%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		k.privHex, s.pubHex, s.entryIP, mullvadPort,
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

func (p *MullvadWireGuardProvider) acquireLease() (Lease, error) {
	idx, k, err := p.checkoutKey()
	if err != nil {
		// No free key: fail fast, same reasoning as NordVPNWireGuardProvider
		// — let MultiVPNProvider try a different VPN source immediately
		// rather than stall waiting for one of this account's 5 keys to
		// free up.
		return Lease{}, err
	}

	var lastErr error
	for attempt := 0; attempt < wgMaxAcquireAttempts; attempt++ {
		s, err := p.nextServer()
		if err != nil {
			p.releaseKey(idx)
			return Lease{}, err
		}
		t0 := time.Now()
		t, err := p.tryOne(k, s)
		if err != nil {
			log.Printf("[mullvad] attempt %d FAIL %s (%s): %v (%.1fs)", attempt, s.hostname, s.entryIP, err, time.Since(t0).Seconds())
			lastErr = err
			continue
		}
		log.Printf("[mullvad] attempt %d OK %s (%s) (%.1fs)", attempt, s.hostname, s.entryIP, time.Since(t0).Seconds())
		p.mu.Lock()
		p.genCtr++
		gen := p.genCtr
		p.live[gen] = t
		p.mu.Unlock()
		p.liveKeyMu.Lock()
		p.liveKey[gen] = idx
		p.liveKeyMu.Unlock()
		return Lease{URL: "socks5://" + t.socks.Addr(), AcquiredAt: time.Now(), Generation: gen}, nil
	}
	p.releaseKey(idx)
	return Lease{}, fmt.Errorf("no working Mullvad server after %d attempts (last: %w)", wgMaxAcquireAttempts, lastErr)
}

func (p *MullvadWireGuardProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	if emit != nil {
		emit("Đang tìm server Mullvad khả dụng…")
	}
	return p.acquireLease()
}

func (p *MullvadWireGuardProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	p.closeLease(oldLease.Generation)
	if emit != nil {
		emit("Đang đổi sang server Mullvad khác…")
	}
	return p.acquireLease()
}

func (p *MullvadWireGuardProvider) Release(workerID int, lease Lease) {
	p.closeLease(lease.Generation)
}

func (p *MullvadWireGuardProvider) closeLease(gen int64) {
	p.mu.Lock()
	t, ok := p.live[gen]
	if ok {
		delete(p.live, gen)
	}
	p.mu.Unlock()

	p.liveKeyMu.Lock()
	idx, hasKey := p.liveKey[gen]
	if hasKey {
		delete(p.liveKey, gen)
	}
	p.liveKeyMu.Unlock()

	if ok {
		t.socks.Close()
		t.dev.Close()
	}
	if hasKey {
		p.releaseKey(idx)
	}
}
