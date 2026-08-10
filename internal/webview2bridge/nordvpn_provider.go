package webview2bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// NordVPNCredentials are the SOCKS5 "service credentials" NordVPN issues
// separately from the account login — the only thing that actually
// authenticates a proxy connection. Fetched once via the access token, not
// per lease.
type NordVPNCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// nordVPNSocksHosts is NordVPN's actual SOCKS5 proxy endpoint list — a
// small, fixed set of dedicated hostnames on the nordhold.net domain, NOT
// the general VPN server list from /v1/servers. That endpoint lists
// thousands of hostnames used to pick a WireGuard/OpenVPN *tunnel*
// server; none of them run a SOCKS5 listener. Confirmed against NordVPN's
// own support docs (support.nordvpn.com "SOCKS5 Proxy" section) after the
// first version of this file — built against /v1/servers hostnames —
// failed every single lease with the browser's egress-IP check timing
// out, regardless of which of the ~8700 tunnel servers got picked.
var nordVPNSocksHosts = []string{
	"nl.socks.nordhold.net",
	"se.socks.nordhold.net",
	"us.socks.nordhold.net",
	"amsterdam.nl.socks.nordhold.net",
	"atlanta.us.socks.nordhold.net",
	"chicago.us.socks.nordhold.net",
	"dallas.us.socks.nordhold.net",
	"los-angeles.us.socks.nordhold.net",
	"new-york.us.socks.nordhold.net",
	"phoenix.us.socks.nordhold.net",
	"san-francisco.us.socks.nordhold.net",
	"stockholm.se.socks.nordhold.net",
}

// nordVPNProxyPort is NordVPN's documented SOCKS5 port — same for every
// socks.nordhold.net hostname above.
const nordVPNProxyPort = "1080"

// NordVPNProvider hands out SOCKS5 leases against NordVPN's fixed proxy
// hostname list, a fresh one per Acquire/rotate call (round-robin).
// Deliberately has no fallback to any other proxy source: if the token is
// bad or NordVPN's credentials API is unreachable, Acquire fails loudly
// instead of silently routing traffic through something else.
//
// Built once at server startup (see cmd/server/main.go) and shared across
// every concurrent request — constructing this per-request would re-fetch
// credentials on every single synthesis call for no benefit, since
// nothing about a request changes what NordVPN hands back.
//
// Deliberately does NOT key leases by workerID the way PoolProvider does:
// workerID only counts up from 0 within a single request's own worker
// pool (see pool.go's `for i := 0; i < cfg.NumWorkers`), so it repeats
// across every concurrent request. PoolProvider gets away with a
// workerID-keyed map because a fresh PoolProvider is built per request;
// this provider is shared, so the same key would collide across unrelated
// requests and hand them each other's lease. Acquire/rotate are stateless
// instead — every call just takes the next hostname off the round-robin,
// which is also cheap enough (no network call, no server-side resource)
// that there's no reason to memoize it per caller.
type NordVPNProvider struct {
	token string

	mu       sync.Mutex
	username string
	password string
	nextIdx  int
	genCtr   int64
}

// NewNordVPNProvider fetches service credentials once. Returns an error if
// that fetch fails — a provider with no credentials can never build a
// working lease, so it's better to fail startup than to come up looking
// healthy and fail every request afterwards.
func NewNordVPNProvider(token string) (*NordVPNProvider, error) {
	p := &NordVPNProvider{token: token}
	if err := p.fetchCredentials(); err != nil {
		return nil, fmt.Errorf("nordvpn credentials: %w", err)
	}
	return p, nil
}

// Close exists for symmetry with the previous version's background
// refresh loop; there's nothing to tear down anymore (no periodic fetch
// left — the hostname list is static and credentials don't need
// re-fetching), but callers that already call it on shutdown stay valid.
func (p *NordVPNProvider) Close() {}

func (p *NordVPNProvider) fetchCredentials() error {
	req, err := http.NewRequest("GET", "https://api.nordvpn.com/v1/users/services/credentials", nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth("token", p.token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var creds NordVPNCredentials
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return err
	}
	if creds.Username == "" || creds.Password == "" {
		return fmt.Errorf("empty service credentials in response")
	}

	p.mu.Lock()
	p.username = creds.Username
	p.password = creds.Password
	p.mu.Unlock()

	masked := creds.Username
	if len(masked) > 8 {
		masked = masked[:8] + "..."
	}
	log.Printf("[NordVPN] Credentials authenticated for user: %s", masked)
	return nil
}

// nextLease builds a Lease from the next hostname in the round-robin.
// Caller must hold p.mu.
func (p *NordVPNProvider) nextLease() (Lease, error) {
	if p.username == "" || p.password == "" {
		return Lease{}, fmt.Errorf("no NordVPN service credentials")
	}
	host := nordVPNSocksHosts[p.nextIdx%len(nordVPNSocksHosts)]
	p.nextIdx++
	u := url.URL{
		Scheme: "socks5",
		User:   url.UserPassword(p.username, p.password),
		Host:   host + ":" + nordVPNProxyPort,
	}
	p.genCtr++
	return Lease{URL: u.String(), AcquiredAt: time.Now(), Generation: p.genCtr}, nil
}

// Acquire hands the worker a fresh NordVPN SOCKS5 endpoint. Each
// concurrent worker — including same-numbered workers from different
// concurrent requests — gets its own round-robin slot; see the type doc
// for why this can't be memoized per workerID.
// Name identifies this source in MultiVPNProvider's per-provider stats
// (see multi_vpn_provider.go).
func (p *NordVPNProvider) Name() string { return "NordVPN-SOCKS5" }

func (p *NordVPNProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	p.mu.Lock()
	lease, err := p.nextLease()
	p.mu.Unlock()
	if err != nil {
		return Lease{}, err
	}
	if emit != nil {
		emit("Đã nhận kết nối NordVPN.")
	}
	return lease, nil
}

// MarkUnhealthyAndRotate hands back a different endpoint. oldLease isn't
// consulted (no shared state to coalesce against — see the type doc);
// every call simply advances to the next round-robin slot.
func (p *NordVPNProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	p.mu.Lock()
	lease, err := p.nextLease()
	p.mu.Unlock()
	if err != nil {
		return Lease{}, err
	}
	if emit != nil {
		emit("Đang đổi sang server NordVPN khác…")
	}
	return lease, nil
}

// Release is a no-op: NordVPN endpoints aren't leased/returned
// server-side the way the old pool's DB rows were, and Acquire keeps no
// per-caller state to clean up.
func (p *NordVPNProvider) Release(workerID int, lease Lease) {}
