//go:build !camoufox

// Package main implements the elevenflow HTTP server — a headless version of
// the desktop app that exposes TTS synthesis via HTTP endpoints. Reuses the
// entire webview2bridge pipeline (WebView2 hCaptcha solving, proxy rotation,
// stealth scripts, ElevenLabs anonymous API calls) without any Wails dependency.
//
// Architecture:
//
//	Docker VPS (web portal worker) → HTTP POST /synthesize → This server
//	This server → WebView2 bridge → hCaptcha + ElevenLabs API → MP3 audio
//	This server → HTTP response (MP3 bytes) → Docker VPS worker
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"elevenflow/internal/proxyserver"
	"elevenflow/internal/webview2bridge"
)

func main() {
	cfg := LoadConfig()

	// Ensure output directory exists for temp files
	if err := os.MkdirAll(cfg.OutputDir, 0o700); err != nil {
		log.Fatalf("Failed to create output directory %s: %v", cfg.OutputDir, err)
	}

	// Initialize proxy lease client — connects to existing Vercel backend
	// for atomic proxy pool management (same as desktop app's startup).
	var proxyClient *proxyserver.Client
	if cfg.ServerURL != "" && cfg.AppSecret != "" {
		proxyClient = proxyserver.New(cfg.ServerURL, cfg.AppSecret)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		pub, err := proxyserver.FetchPublicConfig(ctx, proxyClient.ServerURL())
		cancel()

		if err == nil && pub.CommercialAuth {
			if cfg.UserEmail != "" && cfg.UserPassword != "" {
				loginCtx, loginCancel := context.WithTimeout(context.Background(), 30*time.Second)
				lr, lerr := proxyserver.PasswordLogin(loginCtx, proxyClient.ServerURL(), cfg.AppSecret, cfg.UserEmail, cfg.UserPassword, "elevenflow-server-vps")
				loginCancel()
				if lerr == nil {
					proxyClient.ApplyCommercialSession(lr.AccessToken, lr.RefreshToken, lr.ExpiresIn, lr.UserEmail)
					proxyClient.SetDeviceFingerprint("elevenflow-server-vps")
					log.Printf("Commercial Auth active for user: %s", lr.UserEmail)
				} else {
					log.Printf("Warning: Commercial login failed for %s: %v", cfg.UserEmail, lerr)
				}
			} else {
				log.Println("Warning: Proxy server requires CommercialAuth but ELEVEN_USER_EMAIL / ELEVEN_USER_PASSWORD are not configured")
			}
		} else if proxyClient.HealthCheck(context.Background()) {
			log.Printf("Proxy server connected: %s", cfg.ServerURL)
		} else {
			log.Printf("Warning: proxy server health check failed for %s", cfg.ServerURL)
		}
	} else {
		log.Println("Warning: No proxy server configured (ELEVENFLOW_SERVER_URL / ELEVENFLOW_APP_SECRET)")
	}

	// Built once here (not per-request — see NordVPNProvider's doc comment)
	// and shared across every request. A configured token/credential that
	// fails to authenticate fails startup rather than coming up "healthy"
	// and then failing every synthesis call afterwards: with no pool
	// fallback left once a VPN source is configured, a provider that can't
	// get credentials can never serve a request anyway.
	// Weights below bias MultiVPNProvider's round-robin (see that type —
	// it just cycles a slice in order, so appending a provider N times
	// gives it N/total of the picks, no changes needed there) toward
	// NordVPN: at 8500+ servers it dwarfs PIA's (~360) and Surfshark's
	// (~140) pools, and empirically (2026-08-03 testing) both NordVPN
	// paths were also the fastest/most reliable of the four — the two
	// together are meant to carry most of the system's traffic, with
	// PIA/Surfshark still in the mix for resilience and IP diversity, not
	// eliminated.
	const (
		nordSOCKS5Weight = 2
		nordWGWeight     = 3
		piaWGWeight      = 1
		surfsharkWeight  = 1
	)

	var vpnProviders []webview2bridge.ProxyProvider
	if cfg.NordVPNToken != "" {
		nord, err := webview2bridge.NewNordVPNProvider(cfg.NordVPNToken)
		if err != nil {
			log.Fatalf("NordVPN provider init failed: %v", err)
		}
		for i := 0; i < nordSOCKS5Weight; i++ {
			vpnProviders = append(vpnProviders, nord)
		}
		log.Printf("NordVPN Proxy active with Token: %s... (weight %d)", cfg.NordVPNToken[:8], nordSOCKS5Weight)
	}
	// PIA's plain HTTPS-proxy source (PIAProvider, the 44 fixed
	// serverlist.piaservers.net/proxy hosts) was tried and dropped
	// (2026-08-03, user's call): consistently slow / timing out in
	// production use, unlike PIAWireGuardProvider below which proved
	// fast and reliable once its addKey call was fixed to match PIA's own
	// reference implementation. Left out entirely rather than disabled by
	// config, since there's no reason to keep a known-bad source wired in.
	if cfg.NordVPNToken != "" && cfg.NordVPNWireGuard {
		nordWG, err := webview2bridge.NewNordVPNWireGuardProvider(cfg.NordVPNToken)
		if err != nil {
			log.Fatalf("NordVPN WireGuard provider init failed: %v", err)
		}
		for i := 0; i < nordWGWeight; i++ {
			vpnProviders = append(vpnProviders, nordWG)
		}
		log.Printf("NordVPN WireGuard proxy source active (weight %d, opt-in, heavier per-lease — see doc comment)", nordWGWeight)
	}
	if cfg.PIAUsername != "" && cfg.PIAPassword != "" && cfg.PIAWireGuard {
		piaWG, err := webview2bridge.NewPIAWireGuardProvider(cfg.PIAUsername, cfg.PIAPassword)
		if err != nil {
			log.Fatalf("PIA WireGuard provider init failed: %v", err)
		}
		for i := 0; i < piaWGWeight; i++ {
			vpnProviders = append(vpnProviders, piaWG)
		}
		log.Printf("PIA WireGuard proxy source active (weight %d, opt-in, heavier per-lease — see doc comment)", piaWGWeight)
	}
	if cfg.SurfsharkKey != "" {
		surfshark, err := webview2bridge.NewSurfsharkWireGuardProvider(cfg.SurfsharkKey)
		if err != nil {
			log.Fatalf("Surfshark provider init failed: %v", err)
		}
		for i := 0; i < surfsharkWeight; i++ {
			vpnProviders = append(vpnProviders, surfshark)
		}
		log.Printf("Surfshark WireGuard proxy source active (weight %d)", surfsharkWeight)
	}
	// Combined round-robin when more than one VPN source is configured —
	// every configured source contributes leases instead of only the
	// first one ever being used. A single provider is used directly
	// (skips the extra indirection); none configured leaves this nil,
	// which handler.go treats as "fall back to the old pool" (dev/local
	// runs with no VPN token at all).
	var vpnProvider webview2bridge.ProxyProvider
	switch len(vpnProviders) {
	case 0:
	case 1:
		vpnProvider = vpnProviders[0]
	default:
		vpnProvider = webview2bridge.NewMultiVPNProvider(vpnProviders...)
	}

	// Concurrency semaphore — hard cap on total inflight synthesis requests.
	// Each request uses MaxWorkers WebView2 instances, so actual browser
	// count peaks at MaxConcurrent × MaxWorkers.
	concurrencySem := make(chan struct{}, cfg.MaxConcurrent)

	// Persistent session pool (opt-in, see Config.UsePersistentPool doc
	// comment): a fixed set of WebView2 sessions reused across ALL requests
	// instead of spawned fresh per request. Requires a VPN provider — the
	// old exclusive DB-lease PoolProvider isn't safe to share this way
	// (its Acquire/rotate semantics were built around 1 lease per request,
	// see NordVPNProvider's doc comment on why per-workerID state breaks
	// across concurrent requests).
	var sessionPool *webview2bridge.SessionPool
	if cfg.UsePersistentPool {
		if vpnProvider == nil {
			log.Fatalf("ELEVEN_PERSISTENT_POOL=true requires a VPN provider configured (NordVPN/PIA/Surfshark)")
		}
		numSessions := cfg.PersistentPoolSessions
		if numSessions <= 0 {
			numSessions = cfg.MaxConcurrent * cfg.MaxWorkers
		}
		sp, err := webview2bridge.NewSessionPool(webview2bridge.SessionPoolConfig{
			NumSessions:    numSessions,
			Provider:       vpnProvider,
			IdleCloseAfter: time.Duration(cfg.PersistentPoolIdleCloseSeconds) * time.Second,
		})
		if err != nil {
			log.Fatalf("SessionPool init failed: %v", err)
		}
		sessionPool = sp
		log.Printf("Persistent session pool active: %d sessions, idle-close after %ds",
			numSessions, cfg.PersistentPoolIdleCloseSeconds)
	}

	// Register routes
	mux := http.NewServeMux()
	registerRoutes(mux, cfg, proxyClient, vpnProvider, sessionPool, concurrencySem)

	// Apply middleware stack
	handler := WithMiddlewares(mux, cfg.Secret)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 5 * time.Minute, // Long timeout for synthesis
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		log.Printf("ElevenFlow server starting on :%s", cfg.Port)
		log.Printf("  MaxConcurrent: %d, MaxWorkers/req: %d, ChunkMax: %d chars",
			cfg.MaxConcurrent, cfg.MaxWorkers, cfg.ChunkMaxChars)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Graceful shutdown on SIGINT/SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server (waiting for inflight requests)...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Forced shutdown: %v", err)
	}
	if sessionPool != nil {
		log.Println("Closing persistent session pool...")
		sessionPool.Close()
	}
	log.Println("Server stopped.")
}

func registerRoutes(mux *http.ServeMux, cfg *Config, proxyClient *proxyserver.Client, vpnProvider webview2bridge.ProxyProvider, sessionPool *webview2bridge.SessionPool, concurrencySem chan struct{}) {
	h := &Handler{
		config:         cfg,
		proxyClient:    proxyClient,
		vpnProvider:    vpnProvider,
		sessionPool:    sessionPool,
		concurrencySem: concurrencySem,
	}
	mux.HandleFunc("/synthesize", h.HandleSynthesize(false))
	mux.HandleFunc("/synthesize-srt", h.HandleSynthesize(true))
	mux.HandleFunc("/health", h.HandleHealth)
	mux.HandleFunc("/models", h.HandleModels)
}
