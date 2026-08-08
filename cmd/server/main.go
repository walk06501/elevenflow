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
	// Trọng số chỉnh theo đo thật trên VPS (2026-08-05, cmd/testconcurrency
	// — 30 lease đồng thời, cùng 1 tài khoản/khoá mỗi nguồn). Tiêu chí là
	// tích của HAI thứ, thiếu một trong hai đều vô dụng: (a) chịu được
	// nhiều kết nối ĐỒNG THỜI, (b) có nhiều IP KHÁC NHAU — ElevenLabs gắn
	// cờ detected_unusual_activity khi cùng vài IP gọi liên tục, nên nguồn
	// ít IP không thể gánh tải chính dù nó ổn định đến đâu.
	//
	//   - PIA-WireGuard (6): đo được 30/30 thành công, nhanh nhất (phần lớn
	//     1-2.5s/lease). Mỗi lease tự sinh cặp khoá X25519 mới rồi đăng ký
	//     riêng (xem addKey), nên các kết nối độc lập thật sự trên 361+
	//     server — nguồn đáng tin cậy nhất trong 4 nguồn, gánh phần lớn tải.
	//   - Surfshark (2): CŨNG đo được 30/30 thành công dù dùng CHUNG 1 khoá
	//     tĩnh (giống NordVPN-WG về kiến trúc) — bác bỏ giả thuyết cũ rằng
	//     dùng chung khoá tĩnh ắt bị tranh đường dữ liệu như NordVPN; đó là
	//     giới hạn RIÊNG của backend NordVPN, không phải quy luật chung của
	//     WireGuard. Nhưng độ trễ tăng rõ rệt khi tải cao (7-11s sau lease
	//     thứ ~13, có thể do chỉ ~140 host cố định), nên giữ trọng số vừa
	//     phải, không dồn tải đột biến vào đây.
	//   - NordVPN-SOCKS5 (1): ổn định và nhanh nhất (~2-14s tải xong trang)
	//     nhưng chỉ có 12 host cố định. Dồn tải vào đây sẽ tự chuốc lấy
	//     cờ "hoạt động bất thường" — dùng như đường dự phòng đáng tin, chứ
	//     KHÔNG phải nguồn gánh chính.
	//   - NordVPN-WireGuard (1): 8500+ server nhưng mỗi tài khoản chỉ giữ
	//     được ĐÚNG 1 đường dữ liệu trên phần lớn server (xem
	//     nordWGMaxConcurrentConns) — trừ một số cụm hạ tầng cho đa phiên
	//     thật (đã dò ra bằng cmd/scanwgpools, và NordVPNWireGuardProvider
	//     giờ tự học ưu tiên các cụm đó qua traffic thật, xem
	//     rankedGoodKeysLocked). Vẫn là nguồn yếu nhất trong 4, giữ trọng số
	//     thấp; nhiều tài khoản (ELEVEN_NORDVPN_TOKENS) mới thực sự tăng
	//     được sức chứa, không phải tăng weight.
	//   - ProtonVPN-WireGuard (3): đo được 30/30 thành công (2026-08-05) SAU
	//     KHI sửa 1 lỗi tự gây ra: refreshServers() từng liệt kê nhiều tên
	//     "logical" server trỏ chung 1 EntryIP vật lý (vd SK#1..SK#8 cùng
	//     1 IP) làm nhiều goroutine tự dồn vào đúng 1 endpoint cùng lúc và
	//     timeout handshake lẫn nhau — fix bằng khử trùng lặp theo EntryIP
	//     khi build candidate list (xem doc comment refreshServers). Sau
	//     fix, latency điển hình 5.7-8.5s/lease — chậm hơn PIA rõ rệt
	//     (1-2.5s) nên KHÔNG đặt ngang PIA, nhưng đáng tin hơn Surfshark
	//     (nhiều EntryIP hơn hẳn ~140 host cố định của Surfshark) nên đặt
	//     cao hơn Surfshark một chút.
	const (
		nordSOCKS5Weight = 1
		nordWGWeight     = 1
		piaWGWeight      = 6
		surfsharkWeight  = 2
		protonWGWeight   = 3
	)

	// See loadVPNAccounts (portal_vpn_accounts.go): web-portal's admin
	// console (VPN (ElevenFlow) tab) is the source of truth for every
	// account below, fetched once here at startup; .env only kicks in as a
	// fallback if that fetch itself fails. Every init failure below is now
	// log-and-skip, not Fatalf — the whole point of a remote UI managing
	// these is that a bad credential entered there must not take the whole
	// server down on the next restart.
	vpnAccounts := loadVPNAccounts(cfg)
	nordAccounts := vpnAccounts["nordvpn"]
	piaAccounts := vpnAccounts["pia"]
	surfsharkAccounts := vpnAccounts["surfshark"]
	protonAccounts := vpnAccounts["proton"]
	mullvadAccounts := vpnAccounts["mullvad"]

	var vpnProviders []webview2bridge.ProxyProvider
	if len(nordAccounts) > 0 {
		// SOCKS5 source: fixed shared hosts, not per-account connection-
		// limited like WireGuard (see below), so it gets no benefit from
		// multiple accounts — first account only.
		nordToken := nordAccounts[0].Secret
		nord, err := webview2bridge.NewNordVPNProvider(nordToken)
		if err != nil {
			log.Printf("NordVPN provider init failed, skipping: %v", err)
		} else {
			for i := 0; i < nordSOCKS5Weight; i++ {
				vpnProviders = append(vpnProviders, nord)
			}
			log.Printf("NordVPN Proxy active with Token: %s... (weight %d)", safePrefix(nordToken, 8), nordSOCKS5Weight)
		}
	}
	// PIA's plain HTTPS-proxy source (PIAProvider, the 44 fixed
	// serverlist.piaservers.net/proxy hosts) was tried and dropped
	// (2026-08-03, user's call): consistently slow / timing out in
	// production use, unlike PIAWireGuardProvider below which proved
	// fast and reliable once its addKey call was fixed to match PIA's own
	// reference implementation. Left out entirely rather than disabled by
	// config, since there's no reason to keep a known-bad source wired in.
	if len(nordAccounts) > 0 && cfg.NordVPNWireGuard {
		// One NordVPNWireGuardProvider instance per account: each instance
		// owns its own private key and its own 1-slot semaphore
		// (nordWGMaxConcurrentConns — confirmed by hand, real handshake
		// tests, that a NordVPN account's WireGuard key sustains exactly 1
		// concurrent data path regardless of server or VPS hardware). N
		// accounts therefore means N independent slots, not 1 shared
		// across all of them — the whole reason to add more than one.
		nordWGInit := 0
		for _, a := range nordAccounts {
			nordWG, err := webview2bridge.NewNordVPNWireGuardProvider(a.Secret)
			if err != nil {
				log.Printf("NordVPN WireGuard provider init failed for %s...: %v", safePrefix(a.Secret, 8), err)
				continue
			}
			for i := 0; i < nordWGWeight; i++ {
				vpnProviders = append(vpnProviders, nordWG)
			}
			nordWGInit++
		}
		if nordWGInit > 0 {
			log.Printf("NordVPN WireGuard proxy source active: %d account(s), %d concurrent slot(s) total (weight %d each, opt-in, heavier per-lease — see doc comment)", nordWGInit, nordWGInit, nordWGWeight)
		}
	}
	if len(piaAccounts) > 0 && cfg.PIAWireGuard {
		piaInit := 0
		for _, a := range piaAccounts {
			piaWG, err := webview2bridge.NewPIAWireGuardProvider(a.Username, a.Secret)
			if err != nil {
				log.Printf("PIA WireGuard provider init failed for %s, skipping: %v", a.Username, err)
				continue
			}
			for i := 0; i < piaWGWeight; i++ {
				vpnProviders = append(vpnProviders, piaWG)
			}
			piaInit++
		}
		if piaInit > 0 {
			log.Printf("PIA WireGuard proxy source active: %d account(s) (weight %d each, opt-in, heavier per-lease — see doc comment)", piaInit, piaWGWeight)
		}
	}
	if len(surfsharkAccounts) > 0 {
		sfInit := 0
		for _, a := range surfsharkAccounts {
			surfshark, err := webview2bridge.NewSurfsharkWireGuardProvider(a.Secret)
			if err != nil {
				log.Printf("Surfshark provider init failed, skipping: %v", err)
				continue
			}
			for i := 0; i < surfsharkWeight; i++ {
				vpnProviders = append(vpnProviders, surfshark)
			}
			sfInit++
		}
		if sfInit > 0 {
			log.Printf("Surfshark WireGuard proxy source active: %d account(s) (weight %d each)", sfInit, surfsharkWeight)
		}
	}
	if len(protonAccounts) > 0 && cfg.ProtonWireGuard {
		protonInit := 0
		for _, a := range protonAccounts {
			protonWG, err := webview2bridge.NewProtonVPNWireGuardProvider(a.Username, a.Secret)
			if err != nil {
				log.Printf("ProtonVPN WireGuard provider init failed for %s, skipping: %v", a.Username, err)
				continue
			}
			for i := 0; i < protonWGWeight; i++ {
				vpnProviders = append(vpnProviders, protonWG)
			}
			protonInit++
		}
		if protonInit > 0 {
			log.Printf("ProtonVPN WireGuard proxy source active: %d account(s) (weight %d each, 30/30 confirmed under concurrency after EntryIP-dedup fix — see doc comment)", protonInit, protonWGWeight)
		}
	}
	if len(mullvadAccounts) > 0 && cfg.MullvadWireGuard {
		// No fixed mullvadWGWeight constant like the other four providers:
		// Mullvad's real concurrency ceiling is however many of its 5
		// account-wide key slots registration actually claimed (see
		// MullvadWireGuardProvider.KeyCount doc comment), so each account's
		// weight in the round-robin is read back from the provider itself
		// after a successful init instead of being a number measured once
		// and hardcoded.
		mullvadInit := 0
		for _, a := range mullvadAccounts {
			mullvadWG, err := webview2bridge.NewMullvadWireGuardProvider(a.Secret)
			if err != nil {
				log.Printf("Mullvad WireGuard provider init failed, skipping: %v", err)
				continue
			}
			weight := mullvadWG.KeyCount()
			for i := 0; i < weight; i++ {
				vpnProviders = append(vpnProviders, mullvadWG)
			}
			mullvadInit++
			log.Printf("Mullvad WireGuard proxy source active: account #%d, %d concurrent key slot(s) (weight %d)", mullvadInit, weight, weight)
		}
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
			DataRoot:       cfg.PersistentPoolDataRoot,
		})
		if err != nil {
			log.Fatalf("SessionPool init failed: %v", err)
		}
		sessionPool = sp
		log.Printf("Persistent session pool active: %d sessions, idle-close after %ds, data root %s",
			numSessions, cfg.PersistentPoolIdleCloseSeconds, cfg.PersistentPoolDataRoot)
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

// safePrefix returns the first n bytes of s for logging (never the full
// secret), without panicking when s is shorter than n.
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
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
