package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"elevenflow/internal/proxyserver"
)

// Config holds all server configuration, loaded from environment variables.
type Config struct {
	Port          string // ELEVEN_SERVER_PORT: HTTP listen port (default: 8080)
	Secret        string // ELEVEN_SERVER_SECRET: API auth secret
	MaxWorkers    int    // ELEVEN_MAX_WORKERS: WebView2 instances per request (default: 3)
	MaxConcurrent int    // ELEVEN_MAX_CONCURRENT: Total inflight synthesis requests (default: 50)
	OutputDir     string // ELEVEN_OUTPUT_DIR: Temp directory for audio output (default: ./output)
	ChunkMaxChars int    // ELEVEN_CHUNK_MAX_CHARS: Max characters per chunk (default: 600)
	ServerURL     string // ELEVENFLOW_SERVER_URL: Proxy lease Vercel server
	AppSecret     string // ELEVENFLOW_APP_SECRET: Proxy lease auth secret
	UserEmail     string // ELEVEN_USER_EMAIL: Proxy server account email
	UserPassword  string // ELEVEN_USER_PASSWORD: Proxy server account password

	// PortalAPIURL: web-portal's own API base (e.g. https://sonicvoice.pro/api),
	// NOT this server's own ELEVENFLOW_SERVER_URL/AppSecret above (that's the
	// separate Vercel proxy-lease backend). When set, VPN account credentials
	// (below) are fetched from web-portal's GET /v1/eleven/vpn-accounts at
	// startup — authenticated with this server's own Secret, the same shared
	// secret web-portal's worker already sends for /synthesize — instead of
	// being read from this file. See loadVPNAccounts (portal_vpn_accounts.go).
	PortalAPIURL string // ELEVEN_PORTAL_API_URL

	// Everything below is now SEED / FALLBACK ONLY: authoritative until
	// PortalAPIURL is set and reachable, after which web-portal's admin
	// console (VPN (ElevenFlow) tab) is where accounts are actually managed
	// — edits here are only consulted again if the portal call itself fails
	// at startup (network down, portal down), never once it has succeeded.
	NordVPNToken  string   // ELEVEN_NORDVPN_TOKEN: NordVPN Access Token (first/only account)
	NordVPNTokens []string // ELEVEN_NORDVPN_TOKENS: comma-separated, one per NordVPN account.
	// Each account's WireGuard key sustains exactly 1 concurrent data path
	// on an ordinary server, more on a hand-verified "pool" backend (see
	// nordvpn_wireguard_provider.go's nordWGDefaultMaxConcurrentConns /
	// nordWGPoolKeyCapacity doc) — either way, more accounts is still the
	// only way to multiply that per-account capacity. N accounts here means
	// N separate NordVPNWireGuardProvider instances in main.go, each with
	// its own token/key/slot map, giving N× the slots of one account
	// instead of 1×. Falls back to [NordVPNToken] when unset, so a
	// single-account setup needs no config change.
	PIAUsername      string // ELEVEN_PIA_USERNAME: Private Internet Access account username
	PIAPassword      string // ELEVEN_PIA_PASSWORD: Private Internet Access account password
	NordVPNWireGuard bool   // ELEVEN_NORDVPN_WIREGUARD: also add the WireGuard-tunnel-based NordVPN source (opt-in — heavier per-lease than the SOCKS5 source, see NordVPNWireGuardProvider's doc comment)
	PIAWireGuard     bool   // ELEVEN_PIA_WIREGUARD: also add the WireGuard-tunnel-based PIA source (opt-in — same reasoning as NordVPNWireGuard, see PIAWireGuardProvider's doc comment)
	SurfsharkKey     string // ELEVEN_SURFSHARK_PRIVATE_KEY: Surfshark account's own WireGuard private key (base64) — same key the Surfshark app itself uses, not fetched from any API
	ProtonUsername   string // ELEVEN_PROTON_USERNAME: ProtonVPN account username (2FA must be OFF — no interactive prompt in a server process)
	ProtonPassword   string // ELEVEN_PROTON_PASSWORD: ProtonVPN account password
	ProtonWireGuard  bool   // ELEVEN_PROTON_WIREGUARD: also add the WireGuard-tunnel-based ProtonVPN source (opt-in, unmeasured under concurrency — see ProtonVPNWireGuardProvider's doc comment)
	// MullvadAccountNumber: bare account number (no username/password/2FA —
	// see MullvadWireGuardProvider's doc comment). Only 1 account supported
	// via .env fallback (unlike NordVPNTokens' comma-list) since this whole
	// field is seed/fallback-only — real multi-account Mullvad management is
	// the portal's VPN (ElevenFlow) tab, same as every other provider above.
	MullvadAccountNumber string // ELEVEN_MULLVAD_ACCOUNT
	MullvadWireGuard     bool   // ELEVEN_MULLVAD_WIREGUARD: also add the Mullvad WireGuard source (opt-in, same reasoning as ProtonWireGuard — see MullvadWireGuardProvider's doc comment)

	// IPVanishWireGuard: opt-in gate for IPVanishWireGuardProvider. No
	// account credential to configure — each embedded server in
	// ipvanish_servers.go carries its own dedicated key (see that
	// provider's doc comment for why: neither "one shared key" nor "bulk
	// harvest many keys at once" survived real testing — only hand-
	// verified, individually-registered keys did). Still opt-in rather
	// than always-on since it's unverified under real concurrency — flip
	// on only after confirming with cmd/testconcurrency like the others.
	IPVanishWireGuard bool // ELEVEN_IPVANISH_WIREGUARD

	// CyberGhostUsername/CyberGhostPassword: CyberGhost account credentials
	// (username+password login, like PIA/Proton — see
	// CyberGhostWireGuardProvider's doc comment for the 3-legged auth flow
	// this feeds into). CyberGhostWireGuard opt-in for the same reason as
	// IPVanish/Mullvad/Proton above: unverified under real concurrency
	// until confirmed with cmd/testconcurrency.
	CyberGhostUsername  string // ELEVEN_CYBERGHOST_USERNAME
	CyberGhostPassword  string // ELEVEN_CYBERGHOST_PASSWORD
	CyberGhostWireGuard bool   // ELEVEN_CYBERGHOST_WIREGUARD

	// UsePersistentPool switches HandleSynthesize from the old per-request
	// spawn-then-teardown Run() to webview2bridge.SessionPool — a fixed set
	// of WebView2 sessions kept warm and reused ACROSS requests, only
	// closing a session's window on real idle or on a ban/error, never just
	// because 1 request's batch ended. Opt-in (default off) since it's a
	// new, higher-risk code path on the core request-handling flow — flip on
	// only after verifying on a small slice of real traffic.
	UsePersistentPool bool // ELEVEN_PERSISTENT_POOL

	// PersistentPoolSessions: fixed session count for the pool above. 0 →
	// derive from MaxConcurrent×MaxWorkers, matching today's peak WebView2
	// concurrency ceiling exactly (same capacity, different lifecycle).
	PersistentPoolSessions int // ELEVEN_PERSISTENT_POOL_SESSIONS

	// PersistentPoolIdleCloseSeconds: close a session's WebView2 window
	// (NOT its proxy lease/tunnel — see SessionPool doc comment) after this
	// long without a job, to keep CPU/RAM down when traffic is quiet.
	PersistentPoolIdleCloseSeconds int // ELEVEN_PERSISTENT_POOL_IDLE_CLOSE_SECONDS (default 180)

	// PersistentPoolDataRoot: where SessionPool keeps its WebView2 profile
	// folders. Left unset, webview2bridge.NewSessionPool falls back to
	// os.TempDir() - which resolves to a DIFFERENT path depending on which
	// Windows account is running the process (interactive Administrator vs.
	// SYSTEM via Scheduled Task each get their own %TEMP%). Confirmed live
	// 2026-08-08: the server ran fine for hours started interactively, but
	// crashed instantly on every launch under the SYSTEM-context watchdog
	// task with "Failed to unregister class Chrome_WidgetWin_0" - the
	// SYSTEM-only profile folder had been corrupted by repeated
	// Stop-Process -Force kills during that night's earlier crash-loop
	// incident, and being on disk, survived even a full VPS reboot.
	// Defaulting this to a folder next to the executable (same regardless
	// of which account launches it) makes the profile path identity-
	// independent, so interactive and SYSTEM runs always share the same
	// (working) profile instead of silently using two different ones.
	PersistentPoolDataRoot string // ELEVEN_PERSISTENT_POOL_DATA_ROOT
}

func loadEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if os.Getenv(k) == "" {
				os.Setenv(k, v)
			}
		}
	}
}

func LoadConfig() *Config {
	loadEnvFile(".env")
	return &Config{
		Port:                 getEnv("ELEVEN_SERVER_PORT", "8080"),
		Secret:               getEnv("ELEVEN_SERVER_SECRET", ""),
		MaxWorkers:           getEnvInt("ELEVEN_MAX_WORKERS", 1),
		MaxConcurrent:        getEnvInt("ELEVEN_MAX_CONCURRENT", 50),
		OutputDir:            getEnv("ELEVEN_OUTPUT_DIR", "./output"),
		ChunkMaxChars:        getEnvInt("ELEVEN_CHUNK_MAX_CHARS", 600),
		ServerURL:            getEnv("ELEVENFLOW_SERVER_URL", proxyserver.DefaultServerURL),
		AppSecret:            getEnv("ELEVENFLOW_APP_SECRET", proxyserver.DefaultAppSecret),
		UserEmail:            getEnv("ELEVEN_USER_EMAIL", ""),
		UserPassword:         getEnv("ELEVEN_USER_PASSWORD", ""),
		PortalAPIURL:         getEnv("ELEVEN_PORTAL_API_URL", ""),
		NordVPNToken:         getEnv("ELEVEN_NORDVPN_TOKEN", ""),
		NordVPNTokens:        getEnvTokenList("ELEVEN_NORDVPN_TOKENS", getEnv("ELEVEN_NORDVPN_TOKEN", "")),
		PIAUsername:          getEnv("ELEVEN_PIA_USERNAME", ""),
		PIAPassword:          getEnv("ELEVEN_PIA_PASSWORD", ""),
		NordVPNWireGuard:     getEnv("ELEVEN_NORDVPN_WIREGUARD", "") == "true",
		PIAWireGuard:         getEnv("ELEVEN_PIA_WIREGUARD", "") == "true",
		SurfsharkKey:         getEnv("ELEVEN_SURFSHARK_PRIVATE_KEY", ""),
		ProtonUsername:       getEnv("ELEVEN_PROTON_USERNAME", ""),
		ProtonPassword:       getEnv("ELEVEN_PROTON_PASSWORD", ""),
		ProtonWireGuard:      getEnv("ELEVEN_PROTON_WIREGUARD", "") == "true",
		MullvadAccountNumber: getEnv("ELEVEN_MULLVAD_ACCOUNT", ""),
		MullvadWireGuard:     getEnv("ELEVEN_MULLVAD_WIREGUARD", "") == "true",
		IPVanishWireGuard:    getEnv("ELEVEN_IPVANISH_WIREGUARD", "") == "true",
		CyberGhostUsername:   getEnv("ELEVEN_CYBERGHOST_USERNAME", ""),
		CyberGhostPassword:   getEnv("ELEVEN_CYBERGHOST_PASSWORD", ""),
		CyberGhostWireGuard:  getEnv("ELEVEN_CYBERGHOST_WIREGUARD", "") == "true",

		UsePersistentPool:              getEnv("ELEVEN_PERSISTENT_POOL", "") == "true",
		PersistentPoolSessions:         getEnvInt("ELEVEN_PERSISTENT_POOL_SESSIONS", 0),
		PersistentPoolIdleCloseSeconds: getEnvInt("ELEVEN_PERSISTENT_POOL_IDLE_CLOSE_SECONDS", 180),
		PersistentPoolDataRoot:         getEnv("ELEVEN_PERSISTENT_POOL_DATA_ROOT", defaultPersistentPoolDataRoot()),
	}
}

// defaultPersistentPoolDataRoot picks a WebView2 profile folder anchored to
// the executable's own directory, not os.TempDir() (which resolves
// differently per Windows account - see Config.PersistentPoolDataRoot doc
// comment). Falls back to a relative path if the executable's location
// can't be resolved (should not happen in practice), which at least keeps
// interactive and SYSTEM runs consistent with each other when launched from
// the same working directory.
func defaultPersistentPoolDataRoot() string {
	exe, err := os.Executable()
	if err != nil {
		return "wv2-profiles"
	}
	return filepath.Join(filepath.Dir(exe), "wv2-profiles")
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}

// getEnvTokenList parses a comma-separated env var into a token list,
// trimming whitespace and dropping empty entries. Falls back to `fallback`
// (the legacy singular var's raw value) when the plural var is unset — and
// ALSO comma-splits that fallback, not just wraps it whole, because in
// practice a second account gets pasted onto the singular var (comma and
// all) at least as often as into the plural one. Splitting both the same
// way means whichever var the value landed in, it parses correctly.
func getEnvTokenList(key, fallback string) []string {
	val, ok := os.LookupEnv(key)
	source := val
	if !ok || strings.TrimSpace(val) == "" {
		source = fallback
	}
	if strings.TrimSpace(source) == "" {
		return nil
	}
	var out []string
	for _, tok := range strings.Split(source, ",") {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

func getEnvInt(key string, fallback int) int {
	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		return fallback
	}
	v, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return v
}
