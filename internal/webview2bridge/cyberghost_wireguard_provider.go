package webview2bridge

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// CyberGhostWireGuardProvider mirrors PIAWireGuardProvider's shape almost
// exactly (fresh X25519 keypair per lease, registered live via an addKey
// call, real handshake + real HTTP round trip before trusting the tunnel —
// see that file's doc comment for the shared reasoning), confirmed by
// reverse-engineering CyberGhost's own v2 API live against a real account
// (2026-08-09):
//
//   - Auth is 3-legged, unlike PIA's flat username/password: POST
//     .../v2/my/account/jwt exchanges username+password for a short-lived
//     JWT (needed again on every restart — used for the country/server-
//     list calls, not for addKey), then POST .../v2/my/devices registers
//     a "device" against that JWT and returns a (token, tokenSecret) pair
//     used for every addKey call afterward.
//   - The device registration DOES have a hard per-account cap — confirmed
//     live 2026-08-09 (same class of bug Mullvad's persistence fix exists
//     for, see mullvad_wireguard_provider.go's doc comment): 4 test runs
//     of NewCyberGhostWireGuardProvider each silently registered a BRAND
//     NEW device with no persistence, and the 5th call failed with HTTP
//     403 "The maximum amount of devices was reached." So exactly like
//     Mullvad, the device (token, tokenSecret) pair is persisted to disk
//     (cgDevicePath) and reused on every subsequent startup instead of
//     calling POST /v2/my/devices again — login() still runs every
//     restart (needed for the country-list JWT and appears to carry no
//     cap of its own), only the device-registration call is skipped once
//     a saved device exists.
//   - Every v2-api.cyberghostvpn.com call also needs a static x-app-key
//     header alongside the Bearer JWT. cgAppKey below is CyberGhost's own
//     app-identification value for their official Linux client, found
//     embedded in plain text in ananyatimalsina/cyberghost-linux's
//     src-tauri/src/auth.rs — a legitimate open-source alternate client,
//     not pulled from reversing a compiled binary. It carries no per-user
//     secret.
//   - The server list has no "give me everything" mode: GET
//     .../v2/my/servers/filters/74 requires filter_country (confirmed
//     live — omitting it is a 404 "missing param", not a global list).
//     The full country catalog (GET .../v2/my/servers/countries, 100
//     countries, confirmed non-paginated) is fetched at startup and every
//     one of them is queried in turn for its own WireGuard server list —
//     the operator's own stated priority is proxy/IP diversity over
//     startup speed, so this deliberately does NOT settle for a curated
//     subset. An early attempt at sweeping all 100 in one tight loop
//     (0.3s delay) hit a wall after ~22 requests — every later country
//     came back HTTP 429 "error code: 1015" (Cloudflare's rate-limit
//     signature, confirmed live 2026-08-09), not real zero-server
//     countries (re-querying one of the failed countries alone
//     immediately afterward returned its real, non-empty list). Handled
//     two ways instead of just accepting a smaller pool: a longer
//     inter-request pace (cgCountryFetchDelay) and one retry-after-
//     backoff specifically for 429 responses (cgFetch429RetryDelay)
//     before giving up on a given country — a country failing for any
//     OTHER reason is skipped immediately, since 429 is the one failure
//     mode confirmed transient.
//   - addKey (GET https://<lower(name)>.cg-dialup.net:1337/addKey?pubkey=…,
//     Authorization: Basic base64(token:tokenSecret)) is structurally
//     identical to PIA's: register a fresh pubkey, get back this
//     connection's own peer_ip, the server's WireGuard pubkey, and its
//     real endpoint port (server_port — confirmed live it's 1337, the
//     same port addKey itself is served on, unlike PIA which differs).
//     dns_servers comes back in the same response instead of being a
//     fixed constant the way PIA's is.
//   - addKey's TLS certificate is self-signed per node (CN is the node's
//     internal hostname, e.g. "newyork-rack416.nodes.gen4.ninja", issued
//     by a "CyberGhost Root CA" the server itself does NOT send in the
//     chain) — confirmed live via openssl s_client. Unlike PIA, there is
//     no publicly published root cert to pin (PIA's own
//     pia-foss/manual-connections repo ships ca.rsa.4096.crt; no
//     equivalent CyberGhost repo does), and the cert differs per node
//     rather than being one fixed value this file could embed. Uses
//     InsecureSkipVerify for this one call as a result — the same
//     trade-off an earlier version of PIAWireGuardProvider made before a
//     real pinned CA became available; revisit if CyberGhost's root CA
//     ever surfaces somewhere crackable.
type CyberGhostWireGuardProvider struct {
	username, password string

	mu          sync.Mutex
	token       string
	tokenSecret string
	servers     []cgServer
	// byCountry: last-known-good server list per country, kept across
	// refresh cycles independently of whether THIS cycle's fetch for that
	// country succeeded. refreshServers only overwrites a country's entry
	// when it actually got fresh data — a country that 429s through both
	// its retry and the cleanup pass keeps whatever it had from the last
	// successful fetch (persisted run-to-run too, see the doc comment on
	// refreshServers) rather than dropping out of the pool entirely until
	// the next cycle. servers is always the flattened union of this map.
	byCountry map[string][]cgServer
	nextIdx   int
	genCtr    int64
	live      map[int64]*wgTunnel
}

type cgServer struct {
	name        string // e.g. "NewYork-S416-i01" -> host is strings.ToLower(name)+".cg-dialup.net"
	countryCode string
}

const (
	cgAPIBase = "https://v2-api.cyberghostvpn.com"
	// cgAppKey: see type doc comment — CyberGhost's own Linux-client app
	// key, publicly embedded in an open-source alternate client, not a
	// per-user secret.
	cgAppKey = "QzgDsDNUXlgF9jehkTHHtBJwwI4RyInkZQDRJfLyz"

	// cgCountryFetchDelay: pause between per-country server-list calls.
	// Raised from 600ms to 1.5s on 2026-08-10 after the sweep moved to a
	// background goroutine (see NewCyberGhostWireGuardProvider) — nothing
	// blocks on this anymore, so trading a slower sweep for meaningfully
	// fewer Cloudflare 429s (confirmed live: even 600ms still hit ~9-12/100
	// countries every run, in the same handful of consecutive-streak
	// clusters each time) costs nothing real. Still not a guarantee — see
	// cgFetch429RetryDelay and the cleanup pass in refreshServers for what
	// happens to whatever this doesn't prevent.
	cgCountryFetchDelay = 1500 * time.Millisecond

	// cgFetch429RetryDelay: on a 429 specifically (confirmed transient —
	// see type doc comment), wait this long and retry the SAME country
	// once before giving up on it. Not applied to any other failure kind.
	// Raised from 5s alongside cgCountryFetchDelay for the same reason —
	// a longer backoff before retrying costs nothing now that nothing
	// waits on this sweep.
	cgFetch429RetryDelay = 8 * time.Second
)

// cgCountries: the full country catalog CyberGhost's own GET
// .../v2/my/servers/countries returned live (2026-08-09, 100 countries,
// confirmed non-paginated) — fetching every one maximizes proxy/IP
// diversity, per the operator's own stated priority. Hardcoded rather
// than fetched at every startup because the countries endpoint needs the
// same JWT/device dance as everything else here for no real benefit —
// the set of countries CyberGhost offers changes rarely enough that a
// stale list just means a newly-added country is missed until this is
// refreshed by hand, not a wrong or broken server list.
var cgCountries = []string{
	"IT", "DE", "FR", "CH", "HK", "US", "NL", "KE", "BY", "AL",
	"ES", "GB", "BR", "MX", "IS", "QA", "SE", "SI", "AT", "CL",
	"CR", "MY", "FI", "DK", "BE", "RU", "KZ", "RO", "TH", "CA",
	"JP", "IE", "BD", "LK", "IL", "CO", "HR", "AU", "TW", "VN",
	"BA", "NP", "MM", "LA", "UY", "PE", "GT", "BO", "DO", "EC",
	"SK", "AD", "IN", "KR", "CY", "MT", "GR", "GL", "MC", "NZ",
	"MK", "MD", "HU", "NO", "CZ", "LT", "AE", "EG", "TR", "PH",
	"KH", "SG", "CN", "IM", "LI", "PA", "MA", "GE", "AM", "VE",
	"IR", "MO", "ME", "DZ", "SA", "PK", "AR", "PL", "PT", "NG",
	"BG", "UA", "LV", "ID", "MN", "RS", "EE", "LU", "ZA", "BS",
}

// cgDeviceFilenameSafe replaces characters that don't belong in a filename
// (an email's "@"/"." mainly) so cgDevicePath produces one file per
// CyberGhost account without colliding across accounts.
var cgDeviceFilenameSafe = strings.NewReplacer("@", "_at_", ".", "_", "/", "_", "\\", "_", ":", "_")

// cgDevicePath: a cwd-relative path (NOT %LOCALAPPDATA%/os.UserConfigDir())
// deliberately — same reasoning as mullvadKeysPath (this server runs both
// as a SYSTEM-context Scheduled Task and as a plain interactive process,
// and those resolve per-user paths differently; a cwd-relative path is the
// same file either way since both launch with cwd pinned to the install
// dir). One file per account, since the portal can configure more than one
// CyberGhost account.
func cgDevicePath(username string) string {
	return filepath.Join(".", fmt.Sprintf("cyberghost_device_%s.json", cgDeviceFilenameSafe.Replace(username)))
}

type cgPersistedDevice struct {
	Token       string `json:"token"`
	TokenSecret string `json:"token_secret"`
}

// loadCyberGhostDevice reads a previously-saved device credential pair. A
// missing file (first run ever for this account) is not an error —
// returns "", "", nil so the caller registers a fresh device exactly like
// before this fix existed.
func loadCyberGhostDevice(username string) (token, tokenSecret string, err error) {
	data, err := os.ReadFile(cgDevicePath(username))
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", nil
		}
		return "", "", err
	}
	var d cgPersistedDevice
	if err := json.Unmarshal(data, &d); err != nil {
		return "", "", fmt.Errorf("parse %s: %w", cgDevicePath(username), err)
	}
	return d.Token, d.TokenSecret, nil
}

func saveCyberGhostDevice(username, token, tokenSecret string) error {
	data, err := json.MarshalIndent(cgPersistedDevice{Token: token, TokenSecret: tokenSecret}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cgDevicePath(username), data, 0o600)
}

// cgServersCachePath: same cwd-relative reasoning as cgDevicePath. Caches
// the combined 100-country sweep so a restart doesn't have to pay the
// ~5-6 minute (429-paced) sweep cost again before the server can even
// start — see NewCyberGhostWireGuardProvider's doc comment.
func cgServersCachePath(username string) string {
	return filepath.Join(".", fmt.Sprintf("cyberghost_servers_%s.json", cgDeviceFilenameSafe.Replace(username)))
}

type cgPersistedServer struct {
	Name        string `json:"name"`
	CountryCode string `json:"country_code"`
}

func loadCyberGhostServersCache(username string) ([]cgServer, error) {
	data, err := os.ReadFile(cgServersCachePath(username))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var saved []cgPersistedServer
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("parse %s: %w", cgServersCachePath(username), err)
	}
	servers := make([]cgServer, 0, len(saved))
	for _, s := range saved {
		if s.Name == "" {
			continue
		}
		servers = append(servers, cgServer{name: s.Name, countryCode: s.CountryCode})
	}
	return servers, nil
}

func saveCyberGhostServersCache(username string, servers []cgServer) error {
	saved := make([]cgPersistedServer, len(servers))
	for i, s := range servers {
		saved[i] = cgPersistedServer{Name: s.name, CountryCode: s.countryCode}
	}
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cgServersCachePath(username), data, 0o600)
}

// cgServerRefreshInterval: how often the background loop re-sweeps the
// full 100-country catalog after the first successful load. Country
// server rosters don't churn minute-to-minute, so this is generous —
// the point is "eventually fresh", not "always fresh", since the sweep
// itself costs real time (~5-6 min, 429-paced) and a stale-by-a-few-hours
// list is still a perfectly usable proxy pool.
const cgServerRefreshInterval = 6 * time.Hour

// NewCyberGhostWireGuardProvider logs in, reuses a previously-registered
// device credential pair if one was saved (or registers a fresh one and
// saves it — see type doc comment on why registering fresh every restart
// is not an option, it burns the account's hard device cap), and gets a
// server list ready WITHOUT blocking the caller on the 100-country sweep.
//
// Confirmed live 2026-08-10: the sweep alone takes ~5-6 minutes (429-paced,
// see refreshServers' doc comment) and, before this fix, main.go called
// this constructor synchronously before the HTTP server started listening
// — meaning EVERY restart delayed the entire ElevenFlow server (all six
// VPN sources, not just this one) by 5-6 minutes, even though five of them
// were already fully ready. Fixed two ways:
//  1. The combined server list is cached to disk (cgServersCachePath) after
//     a successful sweep. A restart that finds a cache uses it immediately
//     (synchronously, near-instant) instead of re-sweeping from scratch.
//  2. The actual sweep (fresh on first-ever run, or a periodic refresh
//     every cgServerRefreshInterval afterward) runs in a background
//     goroutine that this function does NOT wait on. A first-ever run for
//     a brand new account genuinely has zero CyberGhost servers for the
//     first ~5-6 minutes (nextCandidate errors, MultiVPNProvider just
//     tries the other five sources meanwhile) — unavoidable once, but
//     never again after the cache exists.
//
// Returns an error only for login/device-credential failures — not having
// a server list YET is not fatal, since the background goroutine will
// populate it (see above).
func NewCyberGhostWireGuardProvider(username, password string) (*CyberGhostWireGuardProvider, error) {
	p := &CyberGhostWireGuardProvider{
		username:  username,
		password:  password,
		live:      map[int64]*wgTunnel{},
		byCountry: map[string][]cgServer{},
	}

	jwt, err := p.login()
	if err != nil {
		return nil, fmt.Errorf("cyberghost login: %w", err)
	}

	token, tokenSecret, loadErr := loadCyberGhostDevice(username)
	if loadErr != nil {
		log.Printf("[CyberGhost-WG] could not read saved device (%v), registering fresh instead", loadErr)
	}
	if token == "" || tokenSecret == "" {
		token, tokenSecret, err = p.registerDevice(jwt)
		if err != nil {
			return nil, fmt.Errorf("cyberghost device registration: %w", err)
		}
		if saveErr := saveCyberGhostDevice(username, token, tokenSecret); saveErr != nil {
			// Not fatal — the newly registered device still works for
			// THIS run, just won't survive to the next restart. Logged
			// loudly since silently reverting to "register fresh every
			// restart" is exactly the failure mode this fix exists to
			// prevent (see type doc comment: 5 restarts exhausted the
			// device cap).
			log.Printf("[CyberGhost-WG] WARNING: could not save device credentials to %s (%v) — next restart will register a fresh device again and may hit the device cap", cgDevicePath(username), saveErr)
		}
	} else {
		log.Printf("[CyberGhost-WG] reusing previously-registered device from %s", cgDevicePath(username))
	}
	p.mu.Lock()
	p.token, p.tokenSecret = token, tokenSecret
	p.mu.Unlock()

	cached, cacheErr := loadCyberGhostServersCache(username)
	if cacheErr != nil {
		log.Printf("[CyberGhost-WG] could not read cached server list (%v), starting with none until background sweep completes", cacheErr)
	} else if len(cached) > 0 {
		p.mu.Lock()
		p.servers = cached
		for _, s := range cached {
			p.byCountry[s.countryCode] = append(p.byCountry[s.countryCode], s)
		}
		p.mu.Unlock()
		log.Printf("[CyberGhost-WG] Ready immediately: %d cached server(s) from %s (refreshing in background)", len(cached), cgServersCachePath(username))
	} else {
		log.Printf("[CyberGhost-WG] no cached server list yet — server starts now, CyberGhost gains capacity once the background sweep completes (~5-6 min)")
	}

	go p.backgroundServerRefreshLoop(username)

	return p, nil
}

// backgroundServerRefreshLoop does the first sweep (if no cache was found,
// or to freshen a cache that was found) and then repeats every
// cgServerRefreshInterval — never blocking NewCyberGhostWireGuardProvider's
// caller. Each cycle re-logs-in for its own JWT rather than reusing the
// constructor's, since a JWT obtained hours ago may well have expired by
// the next scheduled refresh.
func (p *CyberGhostWireGuardProvider) backgroundServerRefreshLoop(username string) {
	for {
		jwt, err := p.login()
		if err != nil {
			log.Printf("[CyberGhost-WG] background refresh: login failed, will retry next cycle: %v", err)
		} else if err := p.refreshServers(jwt); err != nil {
			log.Printf("[CyberGhost-WG] background refresh: server sweep failed, will retry next cycle: %v", err)
		} else {
			p.mu.Lock()
			n := len(p.servers)
			p.mu.Unlock()
			log.Printf("[CyberGhost-WG] Ready: %d server(s) across %d countries", n, len(cgCountries))
			if saveErr := saveCyberGhostServersCache(username, p.serversSnapshot()); saveErr != nil {
				log.Printf("[CyberGhost-WG] WARNING: could not save server cache to %s (%v) — next restart will re-sweep from scratch", cgServersCachePath(username), saveErr)
			}
		}
		time.Sleep(cgServerRefreshInterval)
	}
}

// serversSnapshot returns a copy of the current server list under lock —
// used only for handing data to saveCyberGhostServersCache without racing
// nextCandidate()'s own locked reads.
func (p *CyberGhostWireGuardProvider) serversSnapshot() []cgServer {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]cgServer, len(p.servers))
	copy(out, p.servers)
	return out
}

func (p *CyberGhostWireGuardProvider) Close() {
	p.mu.Lock()
	live := p.live
	p.live = map[int64]*wgTunnel{}
	p.mu.Unlock()
	for _, t := range live {
		t.socks.Close()
		t.dev.Close()
	}
}

// cgHTTPStatusError carries the real HTTP status code through cgDoJSON's
// error return so callers that need to react to a SPECIFIC status (429,
// see refreshServers) can, without string-parsing an error message.
type cgHTTPStatusError struct {
	Status int
	Body   string
}

func (e *cgHTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body)
}

func cgDoJSON(method, u string, headers map[string]string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, u, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// Login and the server-list/countries GETs return 200; device
	// registration (POST /v2/my/devices) returns 201 Created (confirmed
	// live 2026-08-09) — accept any 2xx rather than hardcoding one status
	// per call site.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &cgHTTPStatusError{Status: resp.StatusCode, Body: truncate(string(respBody), 200)}
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("parse response: %w: %s", err, truncate(string(respBody), 200))
		}
	}
	return nil
}

func (p *CyberGhostWireGuardProvider) login() (string, error) {
	var out struct {
		JWT string `json:"jwt"`
	}
	err := cgDoJSON(http.MethodPost, cgAPIBase+"/v2/my/account/jwt?language=en",
		map[string]string{"x-app-key": cgAppKey},
		map[string]string{"userName": p.username, "password": p.password},
		&out)
	if err != nil {
		return "", err
	}
	if out.JWT == "" {
		return "", fmt.Errorf("empty jwt in response")
	}
	log.Printf("[CyberGhost-WG] Logged in as %s", p.username)
	return out.JWT, nil
}

func (p *CyberGhostWireGuardProvider) registerDevice(jwt string) (token, tokenSecret string, err error) {
	var out struct {
		Token       string `json:"token"`
		TokenSecret string `json:"tokenSecret"`
	}
	err = cgDoJSON(http.MethodPost, cgAPIBase+"/v2/my/devices",
		map[string]string{"x-app-key": cgAppKey, "Authorization": "Bearer " + jwt},
		map[string]any{"linuxApp": true, "machineName": ""},
		&out)
	if err != nil {
		return "", "", err
	}
	if out.Token == "" || out.TokenSecret == "" {
		return "", "", fmt.Errorf("empty token/tokenSecret in response")
	}
	return out.Token, out.TokenSecret, nil
}

// fetchCountryServers does one GET for a single country's WireGuard server
// list, retrying exactly once (after cgFetch429RetryDelay) if and only if
// the failure was a 429 — see type doc comment on why 429 specifically is
// treated as transient and nothing else is.
func (p *CyberGhostWireGuardProvider) fetchCountryServers(headers map[string]string, cc string) ([]cgServer, error) {
	var out []struct {
		Name        string `json:"name"`
		CountryCode string `json:"countrycode"`
	}
	u := cgAPIBase + "/v2/my/servers/filters/74?filter_protocol=wireguard&filter_country=" + url.QueryEscape(cc)

	err := cgDoJSON(http.MethodGet, u, headers, nil, &out)
	if err != nil {
		var httpErr *cgHTTPStatusError
		if errors.As(err, &httpErr) && httpErr.Status == http.StatusTooManyRequests {
			log.Printf("[CyberGhost-WG] %s rate-limited (429), retrying once after %s", cc, cgFetch429RetryDelay)
			time.Sleep(cgFetch429RetryDelay)
			err = cgDoJSON(http.MethodGet, u, headers, nil, &out)
		}
		if err != nil {
			return nil, err
		}
	}

	servers := make([]cgServer, 0, len(out))
	for _, s := range out {
		if s.Name == "" {
			continue
		}
		servers = append(servers, cgServer{name: s.Name, countryCode: s.CountryCode})
	}
	return servers, nil
}

// refreshServers fetches every country in cgCountries in turn (see
// cgCountryFetchDelay/cgFetch429RetryDelay doc comments), then makes one
// slower cleanup pass over whatever still failed. This two-pass shape
// exists because Cloudflare's rate limit observed live (2026-08-09) isn't
// simply "N requests total" — it comes in bursty streaks (a run of ~10-20
// consecutive countries all 429ing, then a long clean stretch, then
// another streak), so a country caught in one streak often succeeds fine
// once retried later with the streak's window long expired, even though
// its own immediate cgFetch429RetryDelay retry (5s) landed inside the
// same streak and failed too.
//
// A country still failing after BOTH the per-country retry and this
// cleanup pass does NOT get zeroed out — p.byCountry only gets touched
// for countries this call actually fetched successfully (updateCountry
// below), so a country that fails this entire cycle simply keeps
// whatever server list it already had from a previous successful cycle
// (in-memory from earlier this run, or loaded from disk at startup).
// This matters specifically because backgroundServerRefreshLoop re-sweeps
// ALL 100 countries every cgServerRefreshInterval, not just the ones that
// were missing — without this, a country that's perfectly fine but just
// unlucky enough to 429 during one refresh cycle would vanish from the
// pool for that whole cycle even though its server list from six hours
// ago is still almost certainly valid. Only a country that has NEVER
// once succeeded (no entry in byCountry at all, e.g. first run ever)
// actually contributes zero servers.
func (p *CyberGhostWireGuardProvider) refreshServers(jwt string) error {
	headers := map[string]string{"x-app-key": cgAppKey, "Authorization": "Bearer " + jwt}
	updateCountry := func(cc string, got []cgServer) {
		p.mu.Lock()
		p.byCountry[cc] = got
		p.mu.Unlock()
	}

	var failed []string
	for i, cc := range cgCountries {
		if i > 0 {
			time.Sleep(cgCountryFetchDelay)
		}
		got, err := p.fetchCountryServers(headers, cc)
		if err != nil {
			log.Printf("[CyberGhost-WG] server list for %s failed, will retry in cleanup pass: %v", cc, err)
			failed = append(failed, cc)
			continue
		}
		updateCountry(cc, got)
	}

	if len(failed) > 0 {
		log.Printf("[CyberGhost-WG] cleanup pass: retrying %d countries that failed in the main sweep", len(failed))
		var stillFailed []string
		for i, cc := range failed {
			if i > 0 {
				time.Sleep(cgCountryFetchDelay * 2)
			}
			got, err := p.fetchCountryServers(headers, cc)
			if err != nil {
				stillFailed = append(stillFailed, cc)
				continue
			}
			updateCountry(cc, got)
		}
		if len(stillFailed) > 0 {
			p.mu.Lock()
			var neverSucceeded []string
			for _, cc := range stillFailed {
				if len(p.byCountry[cc]) == 0 {
					neverSucceeded = append(neverSucceeded, cc)
				}
			}
			p.mu.Unlock()
			if len(neverSucceeded) > 0 {
				log.Printf("[CyberGhost-WG] %d/%d countries have NO server list at all (never succeeded): %s", len(neverSucceeded), len(cgCountries), strings.Join(neverSucceeded, ","))
			}
			log.Printf("[CyberGhost-WG] %d/%d countries kept their previous-cycle server list this round (429 through retry + cleanup): %s", len(stillFailed), len(cgCountries), strings.Join(stillFailed, ","))
		}
	}

	p.mu.Lock()
	var servers []cgServer
	for _, list := range p.byCountry {
		servers = append(servers, list...)
	}
	p.servers = servers
	n := len(servers)
	p.mu.Unlock()

	if n == 0 {
		return fmt.Errorf("no servers loaded across %d countries", len(cgCountries))
	}
	return nil
}

func (p *CyberGhostWireGuardProvider) nextCandidate() (cgServer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.servers) == 0 {
		return cgServer{}, fmt.Errorf("no CyberGhost servers loaded")
	}
	s := p.servers[p.nextIdx%len(p.servers)]
	p.nextIdx++
	return s, nil
}

type cgAddKeyResponse struct {
	Status     string   `json:"status"`
	ServerKey  string   `json:"server_key"`
	ServerIP   string   `json:"server_ip"`
	ServerPort int      `json:"server_port"`
	PeerIP     string   `json:"peer_ip"`
	DNSServers []string `json:"dns_servers"`
}

// addKey registers a fresh public key with one CyberGhost server — see
// type doc comment for why InsecureSkipVerify is used here specifically
// (self-signed per-node cert, no publicly pinnable root available).
func (p *CyberGhostWireGuardProvider) addKey(s cgServer, token, tokenSecret, pubKeyB64 string) (*cgAddKeyResponse, error) {
	host := strings.ToLower(s.name) + ".cg-dialup.net"
	u := fmt.Sprintf("https://%s:1337/addKey?pubkey=%s", host, url.QueryEscape(pubKeyB64))
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(token + ":" + tokenSecret))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var out cgAddKeyResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse addKey response: %w: %s", err, truncate(string(body), 200))
	}
	if out.Status != "OK" {
		return nil, fmt.Errorf("addKey status=%q", out.Status)
	}
	return &out, nil
}

// tryOne mirrors PIAWireGuardProvider.tryOne exactly (see that file for
// the full reasoning): fresh keypair, register it, build the tunnel from
// what addKey hands back, wait briefly for a real handshake, then prove
// data actually flows with one real HTTP round trip.
func (p *CyberGhostWireGuardProvider) tryOne(s cgServer, token, tokenSecret string) (*wgTunnel, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())

	ak, err := p.addKey(s, token, tokenSecret, pubB64)
	if err != nil {
		return nil, fmt.Errorf("addKey: %w", err)
	}

	peerAddr, err := netip.ParseAddr(ak.PeerIP)
	if err != nil {
		return nil, fmt.Errorf("bad peer_ip %q: %w", ak.PeerIP, err)
	}
	dnsIP := "10.0.0.243"
	if len(ak.DNSServers) > 0 {
		dnsIP = ak.DNSServers[0]
	}
	dnsAddr, err := netip.ParseAddr(dnsIP)
	if err != nil {
		return nil, fmt.Errorf("bad dns %q: %w", dnsIP, err)
	}

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{peerAddr}, []netip.Addr{dnsAddr}, 1420)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))

	privHex := hex.EncodeToString(priv.Bytes())
	serverPubRaw, err := base64.StdEncoding.DecodeString(ak.ServerKey)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("bad server_key: %w", err)
	}
	serverPubHex := hex.EncodeToString(serverPubRaw)

	port := ak.ServerPort
	if port == 0 {
		port = 1337
	}
	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s:%d\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		privHex, serverPubHex, ak.ServerIP, port,
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

func (p *CyberGhostWireGuardProvider) acquireLease() (Lease, error) {
	p.mu.Lock()
	token, tokenSecret := p.token, p.tokenSecret
	p.mu.Unlock()
	if token == "" || tokenSecret == "" {
		return Lease{}, fmt.Errorf("no CyberGhost device token")
	}

	var lastErr error
	for attempt := 0; attempt < wgMaxAcquireAttempts; attempt++ {
		s, err := p.nextCandidate()
		if err != nil {
			return Lease{}, err
		}
		t, err := p.tryOne(s, token, tokenSecret)
		if err != nil {
			lastErr = fmt.Errorf("%s (%s): %w", s.name, s.countryCode, err)
			continue
		}
		p.mu.Lock()
		p.genCtr++
		gen := p.genCtr
		p.live[gen] = t
		p.mu.Unlock()
		return Lease{URL: "socks5://" + t.socks.Addr(), AcquiredAt: time.Now(), Generation: gen}, nil
	}
	return Lease{}, fmt.Errorf("no working CyberGhost WireGuard server after %d attempts (last: %v)", wgMaxAcquireAttempts, lastErr)
}

// Name identifies this source in MultiVPNProvider's per-provider stats
// (see multi_vpn_provider.go).
func (p *CyberGhostWireGuardProvider) Name() string { return "CyberGhost-WG" }

func (p *CyberGhostWireGuardProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	if emit != nil {
		emit("Đang tìm server CyberGhost (WireGuard) khả dụng…")
	}
	return p.acquireLease()
}

func (p *CyberGhostWireGuardProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	p.closeLease(oldLease.Generation)
	if emit != nil {
		emit("Đang đổi sang server CyberGhost khác…")
	}
	return p.acquireLease()
}

func (p *CyberGhostWireGuardProvider) Release(workerID int, lease Lease) {
	p.closeLease(lease.Generation)
}

func (p *CyberGhostWireGuardProvider) closeLease(gen int64) {
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
