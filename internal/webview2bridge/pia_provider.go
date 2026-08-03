package webview2bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// piaServer is one entry from PIA's public proxy server list.
type piaServer struct {
	Name string `json:"name"`
	ISO  string `json:"iso"`
	DNS  string `json:"dns"`  // hostname to connect to
	Ping string `json:"ping"` // its resolved IP, informational only
	Port int    `json:"port"`
	Mace int    `json:"mace"`
}

// piaServerListURL is PIA's own proxy-specific server list — unlike
// NordVPN, this one really is the right endpoint (the path says "proxy",
// and every entry serves the proxy protocol below), not a VPN tunnel
// server list that happens to also exist. No auth needed to fetch it.
const piaServerListURL = "https://serverlist.piaservers.net/proxy"

// piaTokenURL exchanges the account's real login (not a separate
// "service credential" the way NordVPN does it) for a session token.
const piaTokenURL = "https://www.privateinternetaccess.com/api/client/v2/token"

// PIAProvider hands out HTTPS-proxy leases (PIA's proxy is TLS on :443,
// not SOCKS5 — see localproxy.go's dialUpstream for why that distinction
// matters) built from PIA's own proxy server list, round-robin, one fresh
// server per Acquire/rotate call. No fallback to any other proxy source —
// same reasoning as NordVPNProvider: fail loudly rather than silently
// routing through something else.
//
// Same statelessness/no-workerID-map reasoning as NordVPNProvider (see
// that file's doc comment) — this is meant to be a single shared instance
// across every concurrent request, and workerID repeats across requests.
type PIAProvider struct {
	username string
	password string

	mu        sync.Mutex
	proxyUser string
	proxyPass string
	servers   []piaServer
	nextIdx   int
	genCtr    int64
}

// NewPIAProvider fetches the proxy server list and an auth token once.
// Returns an error if either fails — a provider with no servers or no
// token can never build a working lease.
func NewPIAProvider(username, password string) (*PIAProvider, error) {
	p := &PIAProvider{username: username, password: password}
	if err := p.fetchServers(); err != nil {
		return nil, fmt.Errorf("pia server list: %w", err)
	}
	if err := p.fetchToken(); err != nil {
		return nil, fmt.Errorf("pia token: %w", err)
	}
	return p, nil
}

// Close exists for interface-shape symmetry with NordVPNProvider; nothing
// to tear down (no background loop).
func (p *PIAProvider) Close() {}

func (p *PIAProvider) fetchServers() error {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(piaServerListURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var servers []piaServer
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		return err
	}
	if len(servers) == 0 {
		return fmt.Errorf("empty server list")
	}
	p.mu.Lock()
	p.servers = servers
	p.mu.Unlock()
	log.Printf("[PIA] Loaded %d proxy servers", len(servers))
	return nil
}

// fetchToken exchanges the account login for a session token, then splits
// it in half to use as the actual proxy username/password — this is
// PIA's own documented mechanism for their proxy service, not something
// invented here.
func (p *PIAProvider) fetchToken() error {
	body, _ := json.Marshal(map[string]string{
		"username": p.username,
		"password": p.password,
	})
	req, err := http.NewRequest("POST", piaTokenURL, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
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
	half := len(out.Token) / 2

	p.mu.Lock()
	p.proxyUser = out.Token[:half]
	p.proxyPass = out.Token[half:]
	p.mu.Unlock()

	log.Printf("[PIA] Token acquired for user: %s", p.username)
	return nil
}

// nextLease builds a Lease from the next server in the round-robin.
// Caller must hold p.mu.
func (p *PIAProvider) nextLease() (Lease, error) {
	if len(p.servers) == 0 {
		return Lease{}, fmt.Errorf("no PIA servers loaded")
	}
	if p.proxyUser == "" || p.proxyPass == "" {
		return Lease{}, fmt.Errorf("no PIA proxy token")
	}
	s := p.servers[p.nextIdx%len(p.servers)]
	p.nextIdx++
	u := url.URL{
		Scheme: "https",
		User:   url.UserPassword(p.proxyUser, p.proxyPass),
		Host:   fmt.Sprintf("%s:%d", s.DNS, s.Port),
	}
	p.genCtr++
	return Lease{URL: u.String(), AcquiredAt: time.Now(), Generation: p.genCtr}, nil
}

func (p *PIAProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	p.mu.Lock()
	lease, err := p.nextLease()
	p.mu.Unlock()
	if err != nil {
		return Lease{}, err
	}
	if emit != nil {
		emit("Đã nhận kết nối PIA.")
	}
	return lease, nil
}

func (p *PIAProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	p.mu.Lock()
	lease, err := p.nextLease()
	p.mu.Unlock()
	if err != nil {
		return Lease{}, err
	}
	if emit != nil {
		emit("Đang đổi sang server PIA khác…")
	}
	return lease, nil
}

// Release is a no-op — same reasoning as NordVPNProvider.
func (p *PIAProvider) Release(workerID int, lease Lease) {}
