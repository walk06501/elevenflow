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

	// See Config.FakeFingerprint's doc comment — instant kill switch (.env +
	// restart, no rebuild) for the 2026-08-21 per-window UA/window-size/lang
	// randomization + stealthScript wiring, in case it turns out to hurt
	// hCaptcha pass rate once watched against real traffic.
	webview2bridge.FakeFingerprintEnabled = cfg.FakeFingerprint
	if !cfg.FakeFingerprint {
		log.Println("ELEVEN_FAKE_FINGERPRINT=false — using real UA/1280x800/no stealth script (pre-2026-08-21 behavior)")
	}

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
	//   - CyberGhost-WireGuard (6): đo được 25/25 thành công cùng lúc
	//     (2026-08-09), 2.3-2.7s/lease, KHÔNG chậm lại khi tải cao (kiến trúc
	//     addKey giống hệt PIA — mỗi lease tự sinh khoá riêng, xem
	//     cyberghost_wireguard_provider.go) — đặt ngang PIA vì số đo thực tế
	//     tương đương, dù mới (chỉ 1 tài khoản, chưa chạy dài hạn trên prod).
	//   - Surfshark (2): đo cũ (30/30) dùng CHUNG 1 khoá tĩnh — bác bỏ giả thuyết cũ rằng
	//     dùng chung khoá tĩnh ắt bị tranh đường dữ liệu như NordVPN; đó là
	//     giới hạn RIÊNG của backend NordVPN, không phải quy luật chung của
	//     WireGuard. NHƯNG sau đó rớt xuống 0% kéo dài (2026-08-10), không rõ
	//     nguyên nhân. 2026-08-12: thử sửa sang tự đăng ký khoá mới mỗi lease
	//     qua login+API của Surfshark (nghi ngờ khoá tĩnh cũ hết hạn đăng ký),
	//     nhưng phải REVERT — API đó nằm sau Cloudflare Bot Management, chặn
	//     MỌI client không phải trình duyệt thật (xác nhận từ nhiều IP khác
	//     nhau, không riêng VPS này — xem SurfsharkWireGuardProvider's doc
	//     comment). Quay lại khoá tĩnh do người thật trích xuất qua trình
	//     duyệt, không có cách nào code tự làm mới khoá được nữa. Độ trễ vẫn
	//     tăng rõ khi tải cao trong đo cũ (7-11s sau lease thứ ~13, có thể do
	//     chỉ ~140 host cố định), nên giữ trọng số vừa phải.
	//   - NordVPN-SOCKS5 (1): ổn định và nhanh nhất (~2-14s tải xong trang)
	//     nhưng chỉ có 12 host cố định. Dồn tải vào đây sẽ tự chuốc lấy
	//     cờ "hoạt động bất thường" — dùng như đường dự phòng đáng tin, chứ
	//     KHÔNG phải nguồn gánh chính.
	//   - NordVPN-WireGuard (1): 8500+ server nhưng mỗi tài khoản chỉ giữ
	//     được ĐÚNG 1 đường dữ liệu trên phần lớn server (xem
	//     nordWGDefaultMaxConcurrentConns) — trừ 1 số ít cụm hạ tầng "pool"
	//     đo được chịu NHIỀU đường dữ liệu đồng thời thật (cmd/scanwgpools;
	//     2026-08-11 xác nhận lại: 828-host pool = 10/10 đồng thời, còn
	//     1 pool 61-host = 5/10). Từ 2026-08-11, NordVPNWireGuardProvider
	//     không chỉ HỌC ưu tiên các key đó qua traffic thật
	//     (rankedGoodKeysLocked) mà còn THỰC SỰ cấp nhiều slot đồng thời hơn
	//     cho đúng những key đã chứng minh (nordWGPoolKeyCapacity), tự lùi về
	//     an toàn nếu tỉ lệ thành công SỐNG của key đó tụt (xem
	//     capacityForKeyLocked) — không còn chỉ dựa vào 1 lần đo tĩnh mãi mãi.
	//     Vẫn giữ trọng số thấp vì phần lớn 8500+ server vẫn đúng là 1
	//     đường/tài khoản; nhiều tài khoản (ELEVEN_NORDVPN_TOKENS) vẫn là
	//     cách chính để tăng sức chứa, các pool key chỉ là phần cộng thêm.
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
		// nordSOCKS5Weight: tạm 0 (2026-08-19, thử nghiệm) — operator muốn
		// đo Nord-WG RIÊNG, không để traffic rơi vào SOCKS5 làm loãng tín
		// hiệu (1 job "thành công" qua SOCKS5 không nói lên gì về việc
		// HardCap fix có sửa được contention của WG hay không, và còn kéo
		// bớt tải ra khỏi WG). Bật lại 1 sau khi đo xong.
		nordSOCKS5Weight = 0
		// nordWGWeight: bật lại thăm dò ở 1 sáng 2026-08-19 (sau khi tắt
		// hẳn từ 2026-08-14 vì đo được 11-25% thành công), sau khi sửa MTU
		// 1420→1280. Traffic thật cả ngày (đo riêng từng account nhờ
		// NordVPNWireGuardProvider.Name() giờ có label) cho kết quả VẪN TỆ
		// ở bước Acquire(): NordVPN-WG[#1] 0/3, NordVPN-WG[#2] 1/5 — tổng
		// 1/8 = 12.5%, gần như y hệt mức cũ. QUAN TRỌNG: cả 2 account tệ
		// NHƯ NHAU, không phải 1 account bị hỏng riêng — bác bỏ MTU là
		// nguyên nhân chính, xác nhận lại giả thuyết cũ (2026-08-03):
		// contention/giới hạn 1-đường-dữ-liệu-mỗi-account.
		//
		// Thay vì tắt lại (đã thử, không giải quyết gốc rễ), sửa TẬN GỐC:
		// MultiVPNProvider trước đây cho phép tới weight×vpnCapSlack(3)=3
		// request cùng lúc nhắm vào 1 account chỉ chịu được 1 kết nối —
		// nghĩa là tự tạo ra collision thay vì tránh nó. Nord-WG giờ
		// implement hardCapped (xem NordVPNWireGuardProvider.HardCap),
		// nên cap thực tế = đúng weight = 1/account, không nhân slack:
		// request thứ 2 nhắm cùng account sẽ được xếp SAU các nguồn khác
		// còn rảnh (SOCKS5, account Nord kia) thay vì cứ dí vào chỗ đã bận.
		// Giữ weight=1 (đúng số đường thật), theo dõi vpn_provider_stats
		// per-account ở /health sau deploy để xác nhận cap fix có thực sự
		// nâng được success_rate lên gần mức lý thuyết (2 account = tối đa
		// 2 request đồng thời không collide) hay chưa.
		nordWGWeight = 1
		piaWGWeight  = 6
		// surfsharkWeight: tắt lại 0 (2026-08-21) — stress test thật hôm nay
		// (test_eleven_battery.py, tải đồng thời qua nhiều giờ): 237 lần
		// thử, 0 thành công, ban_failures=0 luôn (không phải bị chặn như
		// các hãng khác đang ~35-50%, mà fail ngay tức khắc, avg_ms=0) —
		// khác hẳn kiểu lỗi 0% hồi 2026-08-10 (key hết hạn, ít nhất còn
		// connect được rồi mới bị từ chối). Giữ 0 cho tới khi điều tra lại
		// bằng cmd/testsurfshark, đừng nâng lại theo phản xạ như lần trước
		// nếu chưa xác nhận nguyên nhân.
		surfsharkWeight = 0
		protonWGWeight  = 3
		// cyberghostWGWeight: hạ từ 6 xuống 1 tạm thời (2026-08-10) — dữ
		// liệu cũ bên dưới (25/25, 2026-08-09) vẫn đúng lúc đo, nhưng
		// stress test thật HÔM NAY cho thấy 0/10 = 0% qua cơ chế thăm dò
		// định kỳ (không phải dữ liệu cũ đóng băng — đã xác nhận đang được
		// thử lại thật), TRÙNG với thời điểm server list refresh liên tục
		// bị Cloudflare 429 trên gần như MỌI quốc gia (không dừng suốt
		// nhiều giờ, pacing 1500ms/8s đã tăng trước đó không đủ). Nghi ngờ
		// IP/tài khoản đang bị chặn diện rộng phía CyberGhost/Cloudflare,
		// không phải lỗi code — cần điều tra riêng trước khi nâng lại. Hạ
		// trọng số (và theo đó, trần đồng thời = weight×3) để giảm lãng phí
		// thời gian/tài nguyên trong lúc chờ, không loại hẳn (cơ chế thăm dò
		// định kỳ vẫn tự phát hiện lúc nó hồi phục).
		//
		// Đo cũ (2026-08-09, cmd/testconcurrency): 25/25 thành công cùng
		// lúc, latency 2.3-2.7s/lease, không tăng khi tải cao. Nếu nguyên
		// nhân gốc được xác nhận đã hết (vd đổi IP, liên hệ CyberGhost),
		// nâng lại 6 và xoá đoạn ghi chú này.
		cyberghostWGWeight = 1
		// proxyxoayWeight: 1 — not a real VPN, a rotating-IP proxy API key
		// (proxyxoay.shop), added 2026-08-18 as a temporary fallback while
		// VPN sources are IP-blocked across their whole range (operator's
		// call). Weight 1 per key means each key's soft concurrent cap is
		// 1×vpnCapSlack (see multi_vpn_provider.go) — matches the operator's
		// "mỗi cửa sổ 1 key xoay" intent without hard-blocking a second
		// concurrent attempt on the same key if everything else is busy.
		proxyxoayWeight = 1
		// ipvanishSocksWeight: SOCKS5 source, same shape as NordVPN-SOCKS5 —
		// fixed shared hosts (18, see ipvanish_socks5_provider.go) behind one
		// shared username/password, not per-account connection-limited like
		// the WireGuard sources. Confirmed live 2026-08-20 (4/4 sampled hosts
		// completed a real HTTP round-trip with 4 distinct exit IPs) but
		// unmeasured under real concurrency — start conservative like the
		// other freshly-added sources, raise once vpn_provider_stats shows a
		// healthy success rate under actual traffic.
		ipvanishSocksWeight = 1
		// homeproxyWeight: same shape as proxyxoay — 1 real identity per
		// key, weight 1 means each key's soft concurrent cap is
		// 1×vpnCapSlack. Candidate vendor under stress-test evaluation
		// 2026-08-22 (operator's call) — see homeproxy_provider.go's doc
		// comment for the vendor contract confirmed live with 5 real keys.
		homeproxyWeight = 1
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
	cyberghostAccounts := vpnAccounts["cyberghost"]
	proxyxoayAccounts := vpnAccounts["proxyxoay"]
	ipvanishSocksAccounts := vpnAccounts["ipvanish_socks5"]
	homeproxyAccounts := vpnAccounts["homeproxy"]

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
	if len(ipvanishSocksAccounts) > 0 {
		// SOCKS5 source: fixed shared hosts, not per-account connection-
		// limited like WireGuard, so it gets no benefit from multiple
		// accounts — first account only, same reasoning as NordVPN-SOCKS5
		// above.
		a := ipvanishSocksAccounts[0]
		ipvanishSocks, err := webview2bridge.NewIPVanishSocksProvider(a.Username, a.Secret)
		if err != nil {
			log.Printf("IPVanish SOCKS5 provider init failed, skipping: %v", err)
		} else {
			for i := 0; i < ipvanishSocksWeight; i++ {
				vpnProviders = append(vpnProviders, ipvanishSocks)
			}
			log.Printf("IPVanish SOCKS5 proxy source active: user %s... (weight %d)", safePrefix(a.Username, 4), ipvanishSocksWeight)
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
		// owns its own private key and its own per-public-key slot map (see
		// nordvpn_wireguard_provider.go's nordWGDefaultMaxConcurrentConns /
		// nordWGPoolKeyCapacity doc — most keys sustain exactly 1 concurrent
		// data path per account, a hand-verified few "pool" keys sustain
		// several). N accounts means N independent copies of that whole
		// per-key slot map, not 1 shared across all of them — the whole
		// reason to add more than one.
		nordWGInit := 0
		for _, a := range nordAccounts {
			nordWG, err := webview2bridge.NewNordVPNWireGuardProvider(a.Secret, a.Label)
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
			log.Printf("NordVPN WireGuard proxy source active: %d account(s) (weight %d each, opt-in, heavier per-lease — see doc comment; per-key slot capacity, not a flat %d concurrent — see nordWGPoolKeyCapacity)", nordWGInit, nordWGWeight, nordWGInit)
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
	if len(cyberghostAccounts) > 0 && cfg.CyberGhostWireGuard {
		cgInit := 0
		for _, a := range cyberghostAccounts {
			cgWG, err := webview2bridge.NewCyberGhostWireGuardProvider(a.Username, a.Secret)
			if err != nil {
				log.Printf("CyberGhost WireGuard provider init failed for %s, skipping: %v", a.Username, err)
				continue
			}
			for i := 0; i < cyberghostWGWeight; i++ {
				vpnProviders = append(vpnProviders, cgWG)
			}
			cgInit++
		}
		if cgInit > 0 {
			log.Printf("CyberGhost WireGuard proxy source active: %d account(s) (weight %d each, opt-in, unverified under concurrency — see doc comment)", cgInit, cyberghostWGWeight)
		}
	}
	if cfg.IPVanishWireGuard {
		// No credential to pass - see NewIPVanishWireGuardProvider's doc
		// comment (each embedded server carries its own key). weight is
		// conservative (unverified under real concurrency, unlike the
		// others which are all tuned from cmd/testconcurrency runs) -
		// bump once confirmed stable under real load.
		const ipvanishWeight = 2
		ipvanish, err := webview2bridge.NewIPVanishWireGuardProvider()
		if err != nil {
			log.Printf("IPVanish WireGuard provider init failed, skipping: %v", err)
		} else {
			for i := 0; i < ipvanishWeight; i++ {
				vpnProviders = append(vpnProviders, ipvanish)
			}
			log.Printf("IPVanish WireGuard proxy source active: %d embedded server(s), weight %d (opt-in, unverified under load — see doc comment)", webview2bridge.IPVanishServerCount(), ipvanishWeight)
		}
	}
	if len(proxyxoayAccounts) > 0 {
		// No opt-in flag (unlike the *WireGuard sources) — this is a plain
		// HTTP proxy client, not a heavy tunnel, and it is here specifically
		// because the operator wants it active right now. One provider
		// instance per key, each with its own background refresh loop (see
		// proxyxoay_provider.go) — no shared state between keys.
		for _, a := range proxyxoayAccounts {
			px := webview2bridge.NewProxyxoayKeyProvider(a.Label, a.Secret, "")
			for i := 0; i < proxyxoayWeight; i++ {
				vpnProviders = append(vpnProviders, px)
			}
		}
		log.Printf("proxyxoay proxy source active: %d key(s) (weight %d each, direct — no Vercel relay)", len(proxyxoayAccounts), proxyxoayWeight)
	}
	if len(homeproxyAccounts) > 0 {
		// Same shape as proxyxoay above — 1 provider instance per key, no
		// background refresh loop needed (see homeproxy_provider.go's doc
		// comment: sticky IP, nothing to keep re-fetching before expiry).
		for _, a := range homeproxyAccounts {
			hp := webview2bridge.NewHomeproxyKeyProvider(a.Label, a.Secret)
			for i := 0; i < homeproxyWeight; i++ {
				vpnProviders = append(vpnProviders, hp)
			}
		}
		log.Printf("homeproxy.vn proxy source active: %d key(s) (weight %d each, direct — candidate under stress-test evaluation)", len(homeproxyAccounts), homeproxyWeight)
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
		// Cap sessions to the number of proxyxoay keys actually available —
		// operator's call, 2026-08-18: each key backs roughly 1 real
		// concurrent identity (see proxyxoay_provider.go's doc comment), so
		// opening more WebView2 windows than that just piles multiple
		// windows onto the SAME underlying IP, which is exactly what caused
		// the ban-rotate storms that got ElevenLabs pulled offline earlier
		// today. cfg.MaxConcurrent (ELEVEN_MAX_CONCURRENT) stays the hard
		// ceiling (15 today) — this only ever SHRINKS numSessions when
		// fewer keys than that are configured, never raises it.
		//
		// 2026-08-22: the cap USED to only count proxyxoay keys, ignoring
		// any other VPN source re-enabled alongside it entirely (operator
		// re-enabled 3 NordVPN-WG accounts as a backup source — this cap
		// kept sessions at 5, so those 3 accounts only ever got used as an
		// occasional mid-session rotate target inside the SAME 5 windows,
		// never opened a window of their own). Now: when proxyxoay AND at
		// least one other VPN source are both active, add
		// cfg.ExtraVPNSessions (ELEVEN_EXTRA_VPN_SESSIONS, default 5) extra
		// slots on top of the proxyxoay-key count — operator's call
		// 2026-08-22: 5 proxyxoay + 5 extra = 10 total when a backup VPN
		// source is present. The extra sessions round-robin across
		// whichever other sources are configured via the same MultiVPNProvider
		// as before (no new plumbing) — each source's own HardCap/cooldown
		// mechanism still governs real concurrency per account, this only
		// controls how many WebView2 windows exist to make lease requests
		// from in the first place.
		// homeproxy (2026-08-22) is the same "1 key = 1 identity" shape as
		// proxyxoay — counts the same way toward the cap.
		identityKeyCount := len(proxyxoayAccounts) + len(homeproxyAccounts)
		otherVPNActive := len(nordAccounts) > 0 || len(piaAccounts) > 0 ||
			len(surfsharkAccounts) > 0 || len(protonAccounts) > 0 ||
			len(mullvadAccounts) > 0 || len(cyberghostAccounts) > 0 ||
			len(ipvanishSocksAccounts) > 0 || cfg.IPVanishWireGuard
		if identityKeyCount > 0 {
			capSessions := identityKeyCount
			extra := 0
			if otherVPNActive {
				extra = cfg.ExtraVPNSessions
				capSessions += extra
			}
			if capSessions < numSessions {
				log.Printf("SessionPool: capping %d -> %d sessions (%d proxyxoay/homeproxy key(s) + %d extra from other active VPN source(s))",
					numSessions, capSessions, identityKeyCount, extra)
				numSessions = capSessions
			}
		}
		sp, err := webview2bridge.NewSessionPool(webview2bridge.SessionPoolConfig{
			NumSessions:    numSessions,
			Provider:       vpnProvider,
			IdleCloseAfter: time.Duration(cfg.PersistentPoolIdleCloseSeconds) * time.Second,
			DataRoot:       cfg.PersistentPoolDataRoot,
			Visible:        cfg.PersistentPoolVisible,
			PrewarmOnStart: cfg.PersistentPoolPrewarm,
		})
		if err != nil {
			log.Fatalf("SessionPool init failed: %v", err)
		}
		sessionPool = sp
		visibleNote := "hidden windows"
		if cfg.PersistentPoolVisible {
			visibleNote = "VISIBLE windows (only actually shows if running interactively, not as a SYSTEM scheduled task)"
		}
		prewarmNote := "prewarm off (lazy cold-start on first job, old behavior)"
		if cfg.PersistentPoolPrewarm {
			prewarmNote = "prewarm ON (cold-starting all sessions now, in the background)"
		}
		log.Printf("Persistent session pool active: %d sessions, idle-close after %ds, data root %s, %s, %s",
			numSessions, cfg.PersistentPoolIdleCloseSeconds, cfg.PersistentPoolDataRoot, visibleNote, prewarmNote)
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
	mux.HandleFunc("/synthesize-progress", h.HandleSynthesizeProgress)
	mux.HandleFunc("/health", h.HandleHealth)
	mux.HandleFunc("/models", h.HandleModels)
}
