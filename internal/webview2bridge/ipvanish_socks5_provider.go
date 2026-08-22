package webview2bridge

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"
)

// ipvanishSocksHosts is IPVanish's SOCKS5 proxy hostname list, from the
// account dashboard's "SOCKS5 Proxy" page (Host Names table) — a small,
// fixed set of dedicated *.socks.ipvanish.com hostnames, completely separate
// from the WireGuard server list in ipvanish_servers.go. Confirmed live
// 2026-08-20: 4/4 sampled hosts (ams, atl, lon, sjc) completed a real HTTP
// round-trip through api.ipify.org with 4 different exit IPs, using the same
// single username/password pair shown on that dashboard page — unlike the
// WireGuard route (see ipvanish_wireguard_provider.go's doc comment), this
// is NOT per-server-key, so it has none of that route's bulk-registration
// dead-key problem.
var ipvanishSocksHosts = []string{
	"mel.socks.ipvanish.com",
	"tor.socks.ipvanish.com",
	"lin.socks.ipvanish.com",
	"ams.socks.ipvanish.com",
	"waw.socks.ipvanish.com",
	"sin.socks.ipvanish.com",
	"mad.socks.ipvanish.com",
	"lon.socks.ipvanish.com",
	"iad.socks.ipvanish.com",
	"atl.socks.ipvanish.com",
	"chi.socks.ipvanish.com",
	"cvg.socks.ipvanish.com",
	"dal.socks.ipvanish.com",
	"lax.socks.ipvanish.com",
	"mia.socks.ipvanish.com",
	"nyc.socks.ipvanish.com",
	"phx.socks.ipvanish.com",
	"sjc.socks.ipvanish.com",
}

// ipvanishSocksPort is IPVanish's documented SOCKS5 port — same for every
// *.socks.ipvanish.com hostname above.
const ipvanishSocksPort = "1080"

// IPVanishSocksProvider hands out SOCKS5 leases against IPVanish's fixed
// proxy hostname list, a fresh one per Acquire/rotate call (round-robin).
// Same shape as NordVPNProvider (nordvpn_provider.go) with one
// simplification: IPVanish's dashboard hands out the SOCKS5
// username/password directly (a "Reset Credentials" button, not a
// token-exchange API), so there's no fetchCredentials step — the pair is
// taken as-is at construction and never re-fetched.
//
// Shared across every concurrent request like NordVPNProvider, for the same
// reason: Acquire/rotate are stateless round-robin picks, cheap enough that
// per-caller memoization would only add complexity for no benefit.
type IPVanishSocksProvider struct {
	username string
	password string

	mu      sync.Mutex
	nextIdx int
	genCtr  int64
}

// NewIPVanishSocksProvider takes the username/password pair as-is from the
// account dashboard. Fails fast if either is empty — a provider with no
// credentials can never build a working lease, so it's better to fail
// startup than come up looking healthy and fail every request afterwards.
func NewIPVanishSocksProvider(username, password string) (*IPVanishSocksProvider, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("ipvanish socks5 username/password required")
	}
	return &IPVanishSocksProvider{username: username, password: password}, nil
}

// Close exists for interface symmetry with the WireGuard-tunnel providers;
// there's nothing to tear down (no tunnel, no background loop).
func (p *IPVanishSocksProvider) Close() {}

// nextLease builds a Lease from the next hostname in the round-robin.
func (p *IPVanishSocksProvider) nextLease() Lease {
	p.mu.Lock()
	host := ipvanishSocksHosts[p.nextIdx%len(ipvanishSocksHosts)]
	p.nextIdx++
	p.genCtr++
	gen := p.genCtr
	p.mu.Unlock()

	u := url.URL{
		Scheme: "socks5",
		User:   url.UserPassword(p.username, p.password),
		Host:   host + ":" + ipvanishSocksPort,
	}
	return Lease{URL: u.String(), AcquiredAt: time.Now(), Generation: gen}
}

// Name identifies this source in MultiVPNProvider's per-provider stats (see
// multi_vpn_provider.go).
func (p *IPVanishSocksProvider) Name() string { return "IPVanish-SOCKS5" }

func (p *IPVanishSocksProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	lease := p.nextLease()
	if emit != nil {
		emit("Đã nhận kết nối IPVanish.")
	}
	return lease, nil
}

// MarkUnhealthyAndRotate hands back a different endpoint. oldLease isn't
// consulted — no shared per-host state to coalesce against, every call
// simply advances to the next round-robin slot (same as NordVPNProvider).
func (p *IPVanishSocksProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, kind FailureKind, emit func(string)) (Lease, error) {
	lease := p.nextLease()
	if emit != nil {
		emit("Đang đổi sang server IPVanish khác…")
	}
	return lease, nil
}

// Release is a no-op: these endpoints aren't leased/returned server-side,
// and Acquire keeps no per-caller state to clean up.
func (p *IPVanishSocksProvider) Release(workerID int, lease Lease) {}
