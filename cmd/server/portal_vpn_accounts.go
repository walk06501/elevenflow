//go:build !camoufox

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// portalVPNAccount is one VPN account as web-portal's GET /v1/eleven/vpn-accounts
// returns it (see web-portal's apps/api/app/routes/eleven_public.py).
// web-portal is now the single source of truth for these credentials — the
// admin console's VPN (ElevenFlow) tab is where they are actually managed,
// not this server's .env. Username is empty for token-only providers
// (nordvpn). Surfshark used to be key-only too but isn't anymore (see
// SurfsharkWireGuardProvider's doc comment, 2026-08-12) — Username/Secret
// here now hold its real login username/password, same shape as pia/proton.
type portalVPNAccount struct {
	Provider string `json:"provider"`
	Label    string `json:"label"`
	Username string `json:"username"`
	Secret   string `json:"secret"`
}

type portalVPNAccountsResponse struct {
	Accounts []portalVPNAccount `json:"accounts"`
}

// fetchVPNAccountsFromPortal calls web-portal's machine-auth endpoint — the
// SAME shared secret this server already checks incoming requests against
// (AuthMiddleware/cfg.Secret) doubles as the credential sent here, per the
// operator's own call to keep this simple rather than provisioning a second
// secret (see web-portal's eleven_public.py docstring for the same
// reasoning from the other side). Groups the flat list by provider so
// main()'s construction loops need no grouping logic of their own.
func fetchVPNAccountsFromPortal(baseURL, secret string, timeout time.Duration) (map[string][]portalVPNAccount, error) {
	url := strings.TrimRight(baseURL, "/") + "/v1/eleven/vpn-accounts"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Api-Secret", secret)

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := string(body)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}

	var parsed portalVPNAccountsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	grouped := make(map[string][]portalVPNAccount)
	for _, a := range parsed.Accounts {
		grouped[a.Provider] = append(grouped[a.Provider], a)
	}
	return grouped, nil
}

func countAccounts(grouped map[string][]portalVPNAccount) int {
	n := 0
	for _, v := range grouped {
		n += len(v)
	}
	return n
}

// envVPNAccounts reproduces the pre-portal behaviour straight from Config's
// seed/fallback fields, so main()'s provider-construction loops have
// exactly one shape (map[provider][]portalVPNAccount) to deal with
// regardless of whether the accounts came from the portal or from .env.
func envVPNAccounts(cfg *Config) map[string][]portalVPNAccount {
	grouped := make(map[string][]portalVPNAccount)
	for i, tok := range cfg.NordVPNTokens {
		grouped["nordvpn"] = append(grouped["nordvpn"], portalVPNAccount{
			Provider: "nordvpn", Label: fmt.Sprintf("nord #%d (.env)", i+1), Secret: tok,
		})
	}
	if cfg.PIAUsername != "" && cfg.PIAPassword != "" {
		grouped["pia"] = append(grouped["pia"], portalVPNAccount{
			Provider: "pia", Label: "pia (.env)", Username: cfg.PIAUsername, Secret: cfg.PIAPassword,
		})
	}
	if cfg.SurfsharkUsername != "" && cfg.SurfsharkPassword != "" {
		grouped["surfshark"] = append(grouped["surfshark"], portalVPNAccount{
			Provider: "surfshark", Label: "surfshark (.env)", Username: cfg.SurfsharkUsername, Secret: cfg.SurfsharkPassword,
		})
	}
	if cfg.ProtonUsername != "" && cfg.ProtonPassword != "" {
		grouped["proton"] = append(grouped["proton"], portalVPNAccount{
			Provider: "proton", Label: "proton (.env)", Username: cfg.ProtonUsername, Secret: cfg.ProtonPassword,
		})
	}
	if cfg.MullvadAccountNumber != "" {
		grouped["mullvad"] = append(grouped["mullvad"], portalVPNAccount{
			Provider: "mullvad", Label: "mullvad (.env)", Secret: cfg.MullvadAccountNumber,
		})
	}
	if cfg.CyberGhostUsername != "" && cfg.CyberGhostPassword != "" {
		grouped["cyberghost"] = append(grouped["cyberghost"], portalVPNAccount{
			Provider: "cyberghost", Label: "cyberghost (.env)", Username: cfg.CyberGhostUsername, Secret: cfg.CyberGhostPassword,
		})
	}
	return grouped
}

// loadVPNAccounts is the one place that decides where VPN credentials come
// from this run: web-portal first when PortalAPIURL is configured, falling
// back to .env only when the portal CALL ITSELF fails (network down, portal
// down, wrong secret) — not when it succeeds but returns zero accounts,
// since an empty portal response is a real "nothing configured" answer, not
// a failure to paper over. Runs once, at startup only — see main.go's doc
// comment on why v1 has no live hot-reload.
func loadVPNAccounts(cfg *Config) map[string][]portalVPNAccount {
	if cfg.PortalAPIURL == "" {
		log.Printf("VPN accounts: ELEVEN_PORTAL_API_URL not set, using .env")
		return envVPNAccounts(cfg)
	}

	grouped, err := fetchVPNAccountsFromPortal(cfg.PortalAPIURL, cfg.Secret, 10*time.Second)
	if err != nil {
		log.Printf("VPN accounts: fetch from portal (%s) failed, falling back to .env: %v", cfg.PortalAPIURL, err)
		fallback := envVPNAccounts(cfg)
		if n := countAccounts(fallback); n > 0 {
			log.Printf("VPN accounts: using .env fallback (%d account(s))", n)
		} else {
			log.Printf("VPN accounts: no .env fallback configured either — starting with 0 VPN sources")
		}
		return fallback
	}

	log.Printf("VPN accounts: loaded %d account(s) from portal (%s)", countAccounts(grouped), cfg.PortalAPIURL)
	return grouped
}
