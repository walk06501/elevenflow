package main

import (
	"os"
	"strconv"
	"strings"

	"elevenflow/internal/proxyserver"
)

// Config holds all server configuration, loaded from environment variables.
type Config struct {
	Port          string   // ELEVEN_SERVER_PORT: HTTP listen port (default: 8080)
	Secret        string   // ELEVEN_SERVER_SECRET: API auth secret
	MaxWorkers    int      // ELEVEN_MAX_WORKERS: WebView2 instances per request (default: 3)
	MaxConcurrent int      // ELEVEN_MAX_CONCURRENT: Total inflight synthesis requests (default: 50)
	OutputDir     string   // ELEVEN_OUTPUT_DIR: Temp directory for audio output (default: ./output)
	ChunkMaxChars int      // ELEVEN_CHUNK_MAX_CHARS: Max characters per chunk (default: 600)
	ServerURL     string   // ELEVENFLOW_SERVER_URL: Proxy lease Vercel server
	AppSecret     string   // ELEVENFLOW_APP_SECRET: Proxy lease auth secret
	UserEmail     string   // ELEVEN_USER_EMAIL: Proxy server account email
	UserPassword  string   // ELEVEN_USER_PASSWORD: Proxy server account password
	NordVPNToken  string   // ELEVEN_NORDVPN_TOKEN: NordVPN Access Token (first/only account)
	NordVPNTokens []string // ELEVEN_NORDVPN_TOKENS: comma-separated, one per NordVPN account.
	// Each account's WireGuard key sustains exactly 1 concurrent data path
	// (see nordvpn_wireguard_provider.go's nordWGMaxConcurrentConns doc) —
	// there is no way to get more concurrent NordVPN-WG slots than accounts.
	// N accounts here means N separate NordVPNWireGuardProvider instances in
	// main.go, each with its own token/key/slot, giving N total slots instead
	// of 1. Falls back to [NordVPNToken] when unset, so a single-account
	// setup needs no config change.
	PIAUsername      string // ELEVEN_PIA_USERNAME: Private Internet Access account username
	PIAPassword      string // ELEVEN_PIA_PASSWORD: Private Internet Access account password
	NordVPNWireGuard bool   // ELEVEN_NORDVPN_WIREGUARD: also add the WireGuard-tunnel-based NordVPN source (opt-in — heavier per-lease than the SOCKS5 source, see NordVPNWireGuardProvider's doc comment)
	PIAWireGuard     bool   // ELEVEN_PIA_WIREGUARD: also add the WireGuard-tunnel-based PIA source (opt-in — same reasoning as NordVPNWireGuard, see PIAWireGuardProvider's doc comment)
	SurfsharkKey     string // ELEVEN_SURFSHARK_PRIVATE_KEY: Surfshark account's own WireGuard private key (base64) — same key the Surfshark app itself uses, not fetched from any API

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
		Port:             getEnv("ELEVEN_SERVER_PORT", "8080"),
		Secret:           getEnv("ELEVEN_SERVER_SECRET", ""),
		MaxWorkers:       getEnvInt("ELEVEN_MAX_WORKERS", 1),
		MaxConcurrent:    getEnvInt("ELEVEN_MAX_CONCURRENT", 50),
		OutputDir:        getEnv("ELEVEN_OUTPUT_DIR", "./output"),
		ChunkMaxChars:    getEnvInt("ELEVEN_CHUNK_MAX_CHARS", 600),
		ServerURL:        getEnv("ELEVENFLOW_SERVER_URL", proxyserver.DefaultServerURL),
		AppSecret:        getEnv("ELEVENFLOW_APP_SECRET", proxyserver.DefaultAppSecret),
		UserEmail:        getEnv("ELEVEN_USER_EMAIL", ""),
		UserPassword:     getEnv("ELEVEN_USER_PASSWORD", ""),
		NordVPNToken:     getEnv("ELEVEN_NORDVPN_TOKEN", ""),
		NordVPNTokens:    getEnvTokenList("ELEVEN_NORDVPN_TOKENS", getEnv("ELEVEN_NORDVPN_TOKEN", "")),
		PIAUsername:      getEnv("ELEVEN_PIA_USERNAME", ""),
		PIAPassword:      getEnv("ELEVEN_PIA_PASSWORD", ""),
		NordVPNWireGuard: getEnv("ELEVEN_NORDVPN_WIREGUARD", "") == "true",
		PIAWireGuard:     getEnv("ELEVEN_PIA_WIREGUARD", "") == "true",
		SurfsharkKey:     getEnv("ELEVEN_SURFSHARK_PRIVATE_KEY", ""),

		UsePersistentPool:              getEnv("ELEVEN_PERSISTENT_POOL", "") == "true",
		PersistentPoolSessions:         getEnvInt("ELEVEN_PERSISTENT_POOL_SESSIONS", 0),
		PersistentPoolIdleCloseSeconds: getEnvInt("ELEVEN_PERSISTENT_POOL_IDLE_CLOSE_SECONDS", 180),
	}
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
