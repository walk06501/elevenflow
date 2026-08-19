package webview2bridge

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-srp"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// ProtonVPNWireGuardProvider: same retry-until-works shape as the other
// three WireGuard providers (see NordVPNWireGuardProvider's doc comment
// for the "no server can be trusted ahead of time" reasoning), but its
// setup is a real login, not a token exchange:
//
//  1. SRP-6a login (email in this codebase's convention, ProtonVPN calls
//     it "Username") via github.com/ProtonMail/go-srp — ProtonMail's own
//     library, so the auth math itself is not hand-rolled here.
//  2. One Ed25519 keypair, generated once at construction and kept for
//     the provider's lifetime — registered as ONE persistent certificate
//     via POST /vpn/v1/certificate. Confirmed by reading Proton's own
//     open-source Linux client (github.com/NordSecurity is NordVPN's;
//     the equivalent for Proton is python-proton-vpn-api-core, mirrored
//     here via github.com/hatemosphere/protonvpn-wg-confgen's Go port)
//     and the community project github.com/Aladex/protonvpn-wg-luci
//     (which documents this exact flow with "verified live" notes after
//     real trial and error): the certificate authorises the KEY across
//     ANY server — only the peer public key/endpoint changes per server,
//     the client key does not need to change.
//  3. WireGuard itself wants an X25519 key, not the Ed25519 one Proton's
//     certificate API requires — ToX25519 below is Proton's own published
//     conversion (github.com/ProtonVPN/go-vpn-lib/ed25519, reproduced
//     directly rather than added as a dependency for ~10 lines): SHA-512
//     the Ed25519 seed, standard X25519 clamp. Getting this wrong is a
//     silent failure, not an error — protonvpn-wg-luci's doc comment
//     records that handing WireGuard the raw Ed25519 seed instead
//     produces a tunnel that LOOKS healthy (handshake completes, the
//     in-tunnel resolver answers) but carries no authorised traffic.
//  4. Server list from GET /vpn/v1/logicals — same one-key-many-servers
//     model as SurfsharkWireGuardProvider, so Acquire() round-robins
//     across physical servers exactly like that provider does.
//
// NOT YET MEASURED: whether one ProtonVPN account/certificate sustains
// more than one concurrent WireGuard data path — the same question
// NordVPN-WG turned out to answer "no" (~1 only, see that file) and PIA/
// Surfshark turned out to answer "yes" (cmd/testconcurrency, 2026-08-05,
// 30/30 both). No community project reviewed while building this one
// (protonvpn-wg-luci, protonvpn-wg-confgen, proton-wg-rotator, and three
// others) ever tries more than one connection at once, so none of them
// answer it either — cmd/testconcurrency already supports "-provider
// proton" for exactly this reason; run it for real before trusting this
// provider under concurrent load the way PIA/Surfshark are trusted today.
type ProtonVPNWireGuardProvider struct {
	httpClient *http.Client
	apiBase    string

	uid   string
	token string

	privHex string // derived X25519 private key, hex — see ToX25519

	mu      sync.Mutex
	servers []protonServer
	nextIdx int
	genCtr  int64
	live    map[int64]*wgTunnel
	// ranker: trí nhớ theo TỪNG server (khoá bằng name) — xem
	// server_ranker.go. Trước 2026-08-10, nextCandidate chỉ round-robin
	// thuần, không nhớ server nào vừa hỏng (kể cả các route Secure Core độ
	// trễ cao đã ghi chú ở protonProbeTimeout phía trên).
	ranker *serverRanker
}

type protonServer struct {
	name    string
	entryIP string
	pubHex  string
}

const (
	protonAPIBase = "https://api.protonvpn.ch"
	protonAddress = "10.2.0.2/32"
	protonDNS     = "10.2.0.1"
	protonPort    = "51820"

	// PM_APPVERSION-equivalent: Proton rejects stale client versions with
	// HTTP 422 / Code 5003. Stamped from the current official Linux
	// client at the time this was written (2026-08-05) — bump if the API
	// starts rejecting it (see protonvpn-wg-luci's api.uc, same constant,
	// same caveat).
	protonAppVersion = "linux-vpn@4.9.0"

	protonCertDuration = "365 days"

	// protonProbeTimeout: the other 3 WireGuard providers share
	// wgProbeTimeout (3s), tuned for their own typical server latency.
	// Proton's own server pool includes higher-latency routes even after
	// excluding Secure Core (protonFeatureSecureCore) — first live test
	// (2026-08-05) missed the shared 3s deadline despite a real, healthy
	// data path (tx=14392 rx=14088 bytes, not a key problem). A wider
	// budget here rather than widening the shared constant, since that
	// constant is already proven correct for NordVPN/PIA/Surfshark.
	protonProbeTimeout = 8 * time.Second
)

// ToX25519 converts an Ed25519 private key (32-byte seed form, as returned
// by crypto/ed25519.PrivateKey.Seed()) to the X25519 secret WireGuard
// wants. Reproduced verbatim from Proton's own published conversion
// (github.com/ProtonVPN/go-vpn-lib/ed25519, MIT-compatible GPL project,
// function ToX25519) rather than pulled in as a dependency for this alone.
func protonToX25519(seed []byte) []byte {
	hash := sha512.Sum512(seed)
	hash[0] &= 0xF8
	hash[31] &= 0x7F
	hash[31] |= 0x40
	return hash[:32]
}

// NewProtonVPNWireGuardProvider logs in via SRP-6a, registers one
// persistent WireGuard certificate, and fetches the server list. Returns
// an error on any step failing — a provider with no session, no
// certificate, or no servers can never build a working lease.
//
// 2FA: if the account has TOTP enabled, login fails here (no interactive
// prompt exists in a server process). Use a dedicated account with 2FA
// off, same as this codebase already does for ELEVEN_USER_EMAIL.
func NewProtonVPNWireGuardProvider(username, password string) (*ProtonVPNWireGuardProvider, error) {
	p := &ProtonVPNWireGuardProvider{
		httpClient: &http.Client{Timeout: 20 * time.Second},
		apiBase:    protonAPIBase,
		live:       map[int64]*wgTunnel{},
		ranker:     newServerRanker("protonvpn:" + username),
	}

	if err := p.login(username, password); err != nil {
		return nil, fmt.Errorf("protonvpn login: %w", err)
	}

	privHex, pubPEM, err := p.newCertificateKeypair()
	if err != nil {
		return nil, fmt.Errorf("protonvpn certificate: %w", err)
	}
	p.privHex = privHex

	if err := p.registerCertificate(pubPEM); err != nil {
		return nil, fmt.Errorf("protonvpn certificate registration: %w", err)
	}

	if err := p.refreshServers(); err != nil {
		return nil, fmt.Errorf("protonvpn server list: %w", err)
	}

	return p, nil
}

func (p *ProtonVPNWireGuardProvider) Close() {
	p.mu.Lock()
	live := p.live
	p.live = map[int64]*wgTunnel{}
	p.mu.Unlock()
	for _, t := range live {
		t.socks.Close()
		t.dev.Close()
	}
}

// ── HTTP plumbing ──────────────────────────────────────────────────────

func (p *ProtonVPNWireGuardProvider) apiCall(method, path string, body, out any) (int, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reqBody = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, p.apiBase+path, reqBody)
	if err != nil {
		return 0, err
	}
	req.Header.Set("x-pm-appversion", protonAppVersion)
	req.Header.Set("Accept", "application/vnd.protonmail.v1+json")
	// Go's http.Client sends "Go-http-client/1.1" by default when no
	// User-Agent is set — an immediate automation tell to Proton's fraud
	// detection (confirmed live 2026-08-05: first-ever login attempt from
	// a VPS IP was rejected as "unusual activity", HTTP 422, on an account
	// with normal prior web-login history — an IP + client-fingerprint
	// signal, not an account-level block). Matches the official Linux
	// client's real UA string.
	req.Header.Set("User-Agent", "ProtonVPN/4.9.0 (Linux; Ubuntu/24.04)")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.uid != "" && p.token != "" {
		req.Header.Set("x-pm-uid", p.uid)
		req.Header.Set("Authorization", "Bearer "+p.token)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, err
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode %s: %w (body: %s)", path, err, truncate(string(respBody), 300))
		}
	}
	return resp.StatusCode, nil
}

// ── SRP-6a login ─────────────────────────────────────────────────────────

type protonAuthInfoResp struct {
	Code            int    `json:"Code"`
	Version         int    `json:"Version"`
	Modulus         string `json:"Modulus"`
	ServerEphemeral string `json:"ServerEphemeral"`
	Salt            string `json:"Salt"`
	SRPSession      string `json:"SRPSession"`
	TwoFA           struct {
		Enabled int `json:"Enabled"`
	} `json:"2FA"`
}

type protonAuthResp struct {
	Code        int    `json:"Code"`
	Error       string `json:"Error"`
	UID         string `json:"UID"`
	AccessToken string `json:"AccessToken"`
	ServerProof string `json:"ServerProof"`
	TwoFactor   int    `json:"TwoFactor"`
}

func (p *ProtonVPNWireGuardProvider) login(username, password string) error {
	var info protonAuthInfoResp
	status, err := p.apiCall(http.MethodPost, "/auth/info", map[string]string{"Username": username}, &info)
	if err != nil {
		return fmt.Errorf("auth/info: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("auth/info: HTTP %d", status)
	}

	auth, err := srp.NewAuth(info.Version, username, []byte(password), info.Salt, info.Modulus, info.ServerEphemeral)
	if err != nil {
		return fmt.Errorf("srp setup: %w", err)
	}
	proofs, err := auth.GenerateProofs(2048)
	if err != nil {
		return fmt.Errorf("srp proofs: %w", err)
	}

	var authResp protonAuthResp
	status, err = p.apiCall(http.MethodPost, "/auth", map[string]string{
		"Username":        username,
		"ClientEphemeral": base64.StdEncoding.EncodeToString(proofs.ClientEphemeral),
		"ClientProof":     base64.StdEncoding.EncodeToString(proofs.ClientProof),
		"SRPSession":      info.SRPSession,
	}, &authResp)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if status != http.StatusOK || authResp.UID == "" || authResp.AccessToken == "" {
		if authResp.Error != "" {
			return fmt.Errorf("auth: %s (HTTP %d)", authResp.Error, status)
		}
		return fmt.Errorf("auth: HTTP %d, incomplete session", status)
	}
	if authResp.TwoFactor != 0 {
		return fmt.Errorf("account has 2FA enabled — use a dedicated account with 2FA off (no interactive prompt in a server process)")
	}
	// ServerProof authenticates the SERVER to us — the SRP handshake is
	// mutual. Not fatal to skip on mismatch here (network issue, not a
	// credential problem), but worth surfacing rather than silently
	// trusting a response that fails its own proof.
	if authResp.ServerProof != base64.StdEncoding.EncodeToString(proofs.ExpectedServerProof) {
		return fmt.Errorf("auth: server proof mismatch (possible MITM or API change)")
	}

	p.uid = authResp.UID
	p.token = authResp.AccessToken
	return nil
}

// ── Certificate (Ed25519 keypair -> WireGuard X25519 key) ────────────────

// newCertificateKeypair generates a fresh Ed25519 keypair and returns the
// derived WireGuard private key (hex, for wgSetConf) alongside the public
// key PEM Proton's certificate endpoint expects.
func (p *ProtonVPNWireGuardProvider) newCertificateKeypair() (privHex string, pubPEM string, err error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", fmt.Errorf("generate ed25519 key: %w", err)
	}
	seed := priv.Seed()
	x25519 := protonToX25519(seed)
	privHex = fmt.Sprintf("%x", x25519)

	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", fmt.Errorf("marshal public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: pkix}
	pubPEM = string(pem.EncodeToMemory(block))
	return privHex, pubPEM, nil
}

type protonCertResp struct {
	Code   int    `json:"Code"`
	Error  string `json:"Error"`
	Serial string `json:"SerialNumber"`
}

// registerCertificate POSTs the public key as a "persistent" (dashboard-
// visible) certificate, matching the request shape confirmed against the
// live API by protonvpn-wg-luci (api.uc's certificate_body): ClientPublicKey,
// ClientPublicKeyMode "EC", Mode "persistent", DeviceName, Duration,
// Features. Renew is deliberately omitted — this is always registering a
// brand new key (one per provider instance), never renewing an existing one.
func (p *ProtonVPNWireGuardProvider) registerCertificate(pubPEM string) error {
	body := map[string]any{
		"ClientPublicKey":     pubPEM,
		"ClientPublicKeyMode": "EC",
		"Mode":                "persistent",
		"DeviceName":          "ElevenFlow",
		"Duration":            protonCertDuration,
		"Features": map[string]any{
			"NetShieldLevel": 0,
			"RandomNAT":      true,
			"PortForwarding": false,
			"SplitTCP":       true,
		},
	}
	var resp protonCertResp
	status, err := p.apiCall(http.MethodPost, "/vpn/v1/certificate", body, &resp)
	if err != nil {
		return err
	}
	if status != http.StatusOK || resp.Serial == "" {
		if resp.Error != "" {
			return fmt.Errorf("%s (HTTP %d)", resp.Error, status)
		}
		return fmt.Errorf("HTTP %d, no serial in response", status)
	}
	return nil
}

// ── Server list ────────────────────────────────────────────────────────

type protonLogicalsResp struct {
	Code           int `json:"Code"`
	LogicalServers []struct {
		Name     string `json:"Name"`
		Status   int    `json:"Status"`
		Features int    `json:"Features"`
		Servers  []struct {
			Status          int    `json:"Status"`
			EntryIP         string `json:"EntryIP"`
			X25519PublicKey string `json:"X25519PublicKey"`
		} `json:"Servers"`
	} `json:"LogicalServers"`
}

// protonFeatureSecureCore: bit 1 of LogicalServer.Features (confirmed
// against github.com/hatemosphere/protonvpn-wg-confgen's api package,
// matching the community-documented bit layout). Secure Core routes
// through 2 hops for extra privacy at the cost of real latency — first
// live test (2026-08-05, server "SE-FR#1", an entry/exit-country-mismatch
// name typical of Secure Core) came back with a WireGuard handshake and
// real bidirectional bytes (tx=14392 rx=14088, ruling out a bad key) but
// still missed the 3s HTTP probe deadline. Excluded here since this
// provider wants many fast exit IPs, not the privacy trade-off.
const protonFeatureSecureCore = 1

func (p *ProtonVPNWireGuardProvider) refreshServers() error {
	var resp protonLogicalsResp
	status, err := p.apiCall(http.MethodGet, "/vpn/v1/logicals", nil, &resp)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("HTTP %d", status)
	}

	// Dedup by EntryIP: Proton's API lists many "logical" server names
	// (e.g. SK#1..SK#8) that resolve to the SAME physical EntryIP within a
	// PoP. Keeping every logical name as a separate round-robin candidate
	// made 30-concurrent runs pile several goroutines onto one physical IP
	// within the same handshake window — confirmed live (2026-08-05): e.g.
	// SK#1,2,3,5,6,7,8 all failed "no handshake within 3s" in the same
	// round while SK#4 (same EntryIP) succeeded a few seconds later, same
	// pattern repeated for GR#1..8, LV#1..8, NL#85..96, NZ#13..20,
	// TW#13..20. One physical endpoint can only field so many brand-new
	// handshakes from this single client key at once — spreading
	// first-attempts across distinct physical IPs (instead of wasting
	// several of the 6 retry slots hammering the same IP) is the fix, the
	// same lesson as NordVPN's public-key pooling.
	seenIP := make(map[string]bool)
	var servers []protonServer
	for _, logical := range resp.LogicalServers {
		if logical.Status != 1 || logical.Features&protonFeatureSecureCore != 0 {
			continue
		}
		for _, s := range logical.Servers {
			if s.Status != 1 || s.EntryIP == "" || s.X25519PublicKey == "" || seenIP[s.EntryIP] {
				continue
			}
			pubHex, err := wgKeyToHex(s.X25519PublicKey)
			if err != nil {
				continue
			}
			seenIP[s.EntryIP] = true
			servers = append(servers, protonServer{name: logical.Name, entryIP: s.EntryIP, pubHex: pubHex})
		}
	}
	if len(servers) == 0 {
		return fmt.Errorf("no online non-SecureCore servers in logicals response")
	}

	p.mu.Lock()
	p.servers = servers
	p.mu.Unlock()
	return nil
}

// ── Tunnel (mirrors SurfsharkWireGuardProvider.tryOne exactly — same
// one-key-many-servers model, same verification: real handshake, then one
// real HTTP round trip, since a completed handshake alone is not proof
// the data path works — protonvpn-wg-luci's doc comment documents exactly
// this failure mode for a wrongly-derived key) ──────────────────────────

// nextCandidate thử server đã chứng minh đáng tin qua traffic thật trước
// (p.ranker.rankedGood, xem server_ranker.go), bỏ qua server đang cooldown
// sau lần fail gần nhất; hết server tốt thì rơi xuống round-robin bình
// thường như cũ.
func (p *ProtonVPNWireGuardProvider) nextCandidate() (protonServer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.servers) == 0 {
		return protonServer{}, fmt.Errorf("no ProtonVPN servers loaded")
	}

	for _, id := range p.ranker.rankedGood() {
		if p.ranker.isPenalized(id) {
			continue
		}
		for _, s := range p.servers {
			if s.name == id {
				return s, nil
			}
		}
	}

	for scanned := 0; scanned < len(p.servers); scanned++ {
		s := p.servers[p.nextIdx%len(p.servers)]
		p.nextIdx++
		if !p.ranker.isPenalized(s.name) {
			return s, nil
		}
	}
	s := p.servers[p.nextIdx%len(p.servers)]
	p.nextIdx++
	return s, nil
}

func (p *ProtonVPNWireGuardProvider) tryOne(s protonServer) (*wgTunnel, error) {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParsePrefix(protonAddress).Addr()},
		[]netip.Addr{netip.MustParseAddr(protonDNS)},
		1420,
	)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))

	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s:%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		p.privHex, s.pubHex, s.entryIP, protonPort,
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

	client := &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext}, Timeout: protonProbeTimeout}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		// Temporary diagnostic (2026-08-05): distinguish "zero bytes ever
		// crossed the tunnel" (points at a wrong/unauthorised key — see
		// this file's doc comment) from "some bytes then a reset" (points
		// elsewhere, e.g. MTU). rx_bytes/tx_bytes come straight from
		// wireguard-go's own IpcGet, not guessed.
		counters := "counters unavailable"
		if info, ierr := dev.IpcGet(); ierr == nil {
			var parts []string
			for _, line := range strings.Split(info, "\n") {
				if strings.HasPrefix(line, "rx_bytes=") || strings.HasPrefix(line, "tx_bytes=") {
					parts = append(parts, line)
				}
			}
			if len(parts) > 0 {
				counters = strings.Join(parts, " ")
			}
		}
		dev.Close()
		return nil, fmt.Errorf("data path check failed: %w [%s]", err, counters)
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

func (p *ProtonVPNWireGuardProvider) acquireLease() (Lease, error) {
	var lastErr error
	for attempt := 0; attempt < wgMaxAcquireAttempts; attempt++ {
		s, err := p.nextCandidate()
		if err != nil {
			return Lease{}, err
		}
		t0 := time.Now()
		t, err := p.tryOne(s)
		p.ranker.noteResult(s.name, err == nil)
		if err != nil {
			log.Printf("[proton] attempt %d FAIL %s (%s): %v (%.1fs)", attempt, s.name, s.entryIP, err, time.Since(t0).Seconds())
			lastErr = fmt.Errorf("%s: %w", s.name, err)
			continue
		}
		log.Printf("[proton] attempt %d OK %s (%s) (%.1fs)", attempt, s.name, s.entryIP, time.Since(t0).Seconds())
		t.hostname = s.name
		p.mu.Lock()
		p.genCtr++
		gen := p.genCtr
		p.live[gen] = t
		p.mu.Unlock()
		return Lease{URL: "socks5://" + t.socks.Addr(), AcquiredAt: time.Now(), Generation: gen}, nil
	}
	return Lease{}, fmt.Errorf("no working ProtonVPN server after %d attempts (last: %v)", wgMaxAcquireAttempts, lastErr)
}

// Name identifies this source in MultiVPNProvider's per-provider stats
// (see multi_vpn_provider.go).
func (p *ProtonVPNWireGuardProvider) Name() string { return "ProtonVPN-WG" }

func (p *ProtonVPNWireGuardProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	if emit != nil {
		emit("Đang tìm server ProtonVPN khả dụng…")
	}
	return p.acquireLease()
}

func (p *ProtonVPNWireGuardProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, kind FailureKind, emit func(string)) (Lease, error) {
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
		emit("Đang đổi sang server ProtonVPN khác…")
	}
	return p.acquireLease()
}

// NoteChunkOK implements networkHealthNotifier (see provider.go).
func (p *ProtonVPNWireGuardProvider) NoteChunkOK(lease Lease) {
	p.mu.Lock()
	t, ok := p.live[lease.Generation]
	p.mu.Unlock()
	if ok && t.hostname != "" {
		p.ranker.noteChunkOK(t.hostname)
	}
}

func (p *ProtonVPNWireGuardProvider) Release(workerID int, lease Lease) {
	p.closeLease(lease.Generation)
}

func (p *ProtonVPNWireGuardProvider) closeLease(gen int64) {
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
