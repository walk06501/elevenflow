package webview2bridge

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// vpnStatsLogInterval: how often the aggregate per-provider summary line
// prints. Matches session_pool.go's statsLogger cadence — frequent enough
// to catch a provider degrading within a shift, not so frequent it drowns
// the per-event rotate lines already printed for every acquire/rotate.
const vpnStatsLogInterval = 5 * time.Minute

// named is implemented by every concrete VPN source so MultiVPNProvider
// can attribute stats to a human-readable name instead of an opaque
// interface value. A source that doesn't implement it (there shouldn't be
// any, but this must never panic) just gets counted under "unknown".
type named interface {
	Name() string
}

func providerName(p ProxyProvider) string {
	if n, ok := p.(named); ok {
		return n.Name()
	}
	return "unknown"
}

// ProviderStat is one VPN source's accumulated Acquire() attempts since
// process start — exported so cmd/server/handler.go can serialize it into
// /health directly. Kept as a plain lifetime counter (never decays) so
// /health always answers "how has this source done overall" — the
// recency-aware view used for live ranking decisions (providerRuntime.recent
// below) is a separate, unexported thing on purpose: mixing "overall" and
// "just now" into one number would make neither question answerable.
type ProviderStat struct {
	Attempts  int64
	Successes int64
	// TotalMs/MaxMs cover SUCCESSFUL attempts only — a failed attempt's
	// duration (e.g. a 90s timeout) would otherwise dominate the average
	// and make a source look "slow" when the real problem is "unreliable",
	// a different thing to fix. Failed-attempt timing is visible via
	// Attempts-Successes and the per-event rotate log lines already
	// printed elsewhere, not folded in here.
	TotalMs int64
	MaxMs   int64
}

// providerRuntime holds the live, decision-relevant state ProviderStat
// deliberately does not: how many leases this source has open RIGHT NOW,
// and how it has done over just the last vpnRankRecentWindow attempts
// (not since process start). Added 2026-08-10 together with the
// capacity-gated ranking below — see that doc comment for the full
// reasoning. Guarded by MultiVPNProvider.mu, same as everything else here.
type providerRuntime struct {
	// active: số lease đang mở thật của nguồn này (tăng lúc RESERVE, tức
	// ngay trước khi thử Acquire() — không đợi thành công — để chặn đúng
	// tình huống 20+ worker cùng nhắm 1 nguồn trong lúc TẤT CẢ còn đang bắt
	// tay, chưa ai kịp thành công để phản ánh vào active).
	active int
	// cap: trần mềm cho active, tính 1 lần lúc khởi tạo từ trọng số
	// (weight) nguồn đó đã được cấu hình trong main.go — xem newProviderCap.
	// "Mềm" vì KHÔNG dùng để từ chối hẳn, chỉ để xếp nguồn đã đầy xuống thử
	// sau (xem rankedProviders) — con số slack nhân với trọng số là phỏng
	// đoán ban đầu, chưa có số đo thật về trần kết nối đồng thời thật của
	// từng tài khoản; mục đích ghi log active/cap mỗi kỳ là để thu thập đủ
	// dữ liệu thật rồi chỉnh lại con số này sau, không phải để đoán đúng
	// ngay từ đầu.
	cap int
	// recent: kết quả vpnRankMinRecentSamples..vpnRankRecentWindow lần thử
	// GẦN NHẤT (true = thành công), cũ nhất bị đẩy ra khi đầy. Khác
	// ProviderStat.Attempts/Successes ở chỗ đây là cửa sổ trượt, không phải
	// cộng dồn cả đời — 1 nguồn có lịch sử tốt lâu năm vẫn phải "trả giá"
	// nhanh khi vừa có 1 đợt fail dồn dập, không bị lịch sử cũ che mất.
	recent []bool
}

func (pr *providerRuntime) pushRecent(ok bool) {
	pr.recent = append(pr.recent, ok)
	if len(pr.recent) > vpnRankRecentWindow {
		pr.recent = pr.recent[len(pr.recent)-vpnRankRecentWindow:]
	}
}

func (pr *providerRuntime) recentRate() (rate float64, n int) {
	n = len(pr.recent)
	if n == 0 {
		return 0, 0
	}
	ok := 0
	for _, v := range pr.recent {
		if v {
			ok++
		}
	}
	return float64(ok) / float64(n), n
}

// MultiVPNProvider round-robins across several VPN-backed ProxyProviders
// (NordVPN, PIA, ...) so every configured source contributes leases
// instead of only the first one ever being used. Each call just delegates
// to the next provider in line — the providers themselves already handle
// their own round-robin over hostnames.
//
// Mỗi lease phát ra được gắn kèm provider đã cấp nó (Lease.owner) vì
// Release/MarkUnhealthyAndRotate BẮT BUỘC phải quay lại đúng provider đó:
// các provider WireGuard (NordVPN-WG/PIA-WG/Surfshark) giữ tunnel thật
// trong map theo Generation, mà Generation chỉ duy nhất trong phạm vi từng
// provider. Gọi nhầm provider vừa không đóng được tunnel cần đóng, vừa có
// thể đóng nhầm tunnel của provider khác đang dùng tốt.
//
// Also accumulates per-provider Acquire() attempt/success/timing stats
// (see ProviderStat) and logs a periodic aggregate summary — added
// 2026-08-10 after the operator asked to distinguish "this provider gets
// picked often because of its weight" from "this provider actually fails
// or is actually slow more than the others", something raw per-event log
// lines cannot answer on their own (25 concurrent workers interleave their
// output, and a provider's weight — not its reliability — is what mostly
// determines how often it shows up as a rotate target).
type MultiVPNProvider struct {
	mu        sync.Mutex
	providers []ProxyProvider
	next      int
	stats     map[string]*ProviderStat
	runtime   map[string]*providerRuntime
	// exploreCounter: tăng mỗi lần rankedProviders() được gọi — cứ mỗi
	// vpnExploreEveryN lần thì đảo ngược ưu tiên tốt/tệ, xem doc comment
	// vpnExploreEveryN.
	exploreCounter int64
}

// newProviderCap tính trần mềm cho 1 nguồn từ trọng số nó xuất hiện trong
// danh sách providers (main.go append 1 provider nhiều lần để đánh trọng
// số — xem distinctProviders). vpnCapSlack nhân thêm để "tận dụng tối đa
// tài nguyên" thay vì khoá cứng đúng bằng trọng số gốc: 1 nguồn đang chạy
// tốt được phép gánh nhiều hơn tỉ trọng gốc của nó khi các nguồn khác đang
// tệ, chỉ bị chặn khi thực sự vượt xa mức đó.
func newProviderCap(weight int) int {
	if weight < 1 {
		weight = 1
	}
	return weight * vpnCapSlack
}

func NewMultiVPNProvider(providers ...ProxyProvider) *MultiVPNProvider {
	weight := map[string]int{}
	for _, p := range providers {
		weight[providerName(p)]++
	}
	runtime := make(map[string]*providerRuntime, len(weight))
	for name, w := range weight {
		runtime[name] = &providerRuntime{cap: newProviderCap(w)}
	}
	m := &MultiVPNProvider{
		providers: providers,
		stats:     map[string]*ProviderStat{},
		runtime:   runtime,
	}
	go m.statsLogger()
	return m
}

// distinctProviders trả về danh sách provider KHÔNG TRÙNG, theo thứ tự
// round-robin bắt đầu từ vị trí hiện tại. Cần lọc trùng vì main.go cố tình
// append 1 provider nhiều lần để đánh trọng số (xem khối weight ở đó) —
// thử lại đúng provider vừa lỗi thì chỉ tốn thêm thời gian.
func (m *MultiVPNProvider) distinctProviders() []ProxyProvider {
	m.mu.Lock()
	start := m.next
	m.next++
	all := make([]ProxyProvider, 0, len(m.providers))
	seen := make(map[ProxyProvider]bool, len(m.providers))
	for i := 0; i < len(m.providers); i++ {
		p := m.providers[(start+i)%len(m.providers)]
		if seen[p] {
			continue
		}
		seen[p] = true
		all = append(all, p)
	}
	m.mu.Unlock()
	return all
}

// runtimeFor trả về providerRuntime của 1 tên nguồn, tạo mới nếu chưa có
// (phòng trường hợp providerName trả "unknown" hoặc 1 nguồn không nằm
// trong danh sách lúc New — không nên xảy ra nhưng không được panic).
// Caller must hold m.mu.
func (m *MultiVPNProvider) runtimeFor(name string) *providerRuntime {
	rt, ok := m.runtime[name]
	if !ok {
		rt = &providerRuntime{cap: newProviderCap(1)}
		m.runtime[name] = rt
	}
	return rt
}

// reserve đánh dấu 1 slot đang được dùng bởi `name` NGAY TRƯỚC khi thử
// Acquire() — không đợi thành công. Đây là điểm mấu chốt chặn dồn tải:
// nếu chờ tới lúc thành công mới tăng active, 20+ worker cùng chọn 1 nguồn
// trong lúc tất cả còn đang bắt tay sẽ không thấy nhau, mỗi worker đều
// thấy nguồn đó "còn chỗ". Reserve() luôn thành công (không từ chối) —
// cap chỉ ảnh hưởng thứ tự thử ở rankedProviders, không chặn cứng ở đây.
func (m *MultiVPNProvider) reserve(name string) {
	m.mu.Lock()
	m.runtimeFor(name).active++
	m.mu.Unlock()
}

// releaseActive trả 1 slot lại cho `name` — gọi khi 1 lần thử thất bại
// ngay lập tức (không bao giờ giữ lease), hoặc khi 1 lease đã cấp được
// đóng/giao trả (Release/MarkUnhealthyAndRotate).
func (m *MultiVPNProvider) releaseActive(name string) {
	m.mu.Lock()
	rt := m.runtimeFor(name)
	if rt.active > 0 {
		rt.active--
	}
	m.mu.Unlock()
}

// recordAttempt ghi 1 kết quả thật vào cả 2 nơi: ProviderStat (cộng dồn cả
// đời, dùng cho /health) và providerRuntime.recent (cửa sổ trượt, dùng để
// xếp hạng — xem doc comment providerRuntime).
func (m *MultiVPNProvider) recordAttempt(name string, ok bool, dur time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, exists := m.stats[name]
	if !exists {
		st = &ProviderStat{}
		m.stats[name] = st
	}
	st.Attempts++
	if ok {
		st.Successes++
		ms := dur.Milliseconds()
		st.TotalMs += ms
		if ms > st.MaxMs {
			st.MaxMs = ms
		}
	}
	m.runtimeFor(name).pushRecent(ok)
}

// Stats returns a snapshot of attempt/success/timing counts per VPN
// source name, accumulated since process start (never reset — this
// process's whole lifetime is the window, same convention as
// NordVPNWireGuardProvider's in-memory keyStats). Exposed via /health.
func (m *MultiVPNProvider) Stats() map[string]ProviderStat {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]ProviderStat, len(m.stats))
	for name, st := range m.stats {
		out[name] = *st
	}
	return out
}

// statsLogger prints one aggregate line per vpnStatsLogInterval, sorted
// worst-recent-rate-first — the point of glancing at this line is spotting
// a degrading source, so the one most worth looking at belongs at the
// front, not buried after five healthy ones in alphabetical order. Prints
// BOTH the lifetime rate (ProviderStat, cả đời) and the recent-window rate
// (providerRuntime.recent, vpnRankRecentWindow lần gần nhất) side by side
// so a diverging pair (lifetime cao, recent thấp) is visible directly in
// the log without needing a separate query — cộng thêm active/cap để thấy
// ngay nguồn nào đang gần/đã chạm trần mềm tại đúng thời điểm log in ra.
func (m *MultiVPNProvider) statsLogger() {
	t := time.NewTicker(vpnStatsLogInterval)
	defer t.Stop()
	for range t.C {
		m.mu.Lock()
		type row struct {
			name         string
			st           ProviderStat
			lifetimeRate float64
			recentRate   float64
			recentN      int
			active, cap  int
		}
		rows := make([]row, 0, len(m.stats))
		for name, st := range m.stats {
			lifetimeRate := 1.0
			if st.Attempts > 0 {
				lifetimeRate = float64(st.Successes) / float64(st.Attempts)
			}
			rt := m.runtimeFor(name)
			rRate, rN := rt.recentRate()
			rows = append(rows, row{name, *st, lifetimeRate, rRate, rN, rt.active, rt.cap})
		}
		m.mu.Unlock()
		if len(rows) == 0 {
			continue
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].recentRate < rows[j].recentRate })

		parts := make([]string, 0, len(rows))
		for _, r := range rows {
			avgMs := int64(0)
			if r.st.Successes > 0 {
				avgMs = r.st.TotalMs / r.st.Successes
			}
			parts = append(parts, fmt.Sprintf(
				"%s: recent=%.0f%%(%d) lifetime=%d/%d(%.0f%%) active=%d/%d tb=%.1fs max=%.1fs",
				r.name, r.recentRate*100, r.recentN,
				r.st.Successes, r.st.Attempts, r.lifetimeRate*100,
				r.active, r.cap,
				float64(avgMs)/1000, float64(r.st.MaxMs)/1000,
			))
		}
		log.Printf("[vpn-stats] %s", strings.Join(parts, " | "))
	}
}

// Ngưỡng xếp hạng/chặn quá tải — thêm 2026-08-10. Thiết kế 2 lớp, lớp 1 áp
// trước lớp 2:
//
//  1. Chặn quá tải đồng thời (active/cap, xem providerRuntime.cap): 1 nguồn
//     đang có active >= cap bị đẩy xuống thử SAU mọi nguồn còn dưới cap,
//     bất kể đang chạy tốt hay tệ. Đây là thứ ranking-theo-tỉ-lệ-thuần-tuý
//     (bản trước, chỉ có lớp 2) không có: nếu chỉ xếp theo tỉ lệ thành
//     công, 1 nguồn đang chạy tốt sẽ bị TẤT CẢ worker cùng ưu tiên thử
//     cùng lúc, có thể tự nó gây quá tải/chạm trần kết nối thật của chính
//     tài khoản đó — hỏng vì bị chọn quá nhiều, không phải vì nó tệ.
//  2. Trong từng nhóm (dưới cap, rồi tới đã đầy cap), xếp tiếp theo tỉ lệ
//     thành công CỦA CỬA SỔ GẦN ĐÂY (providerRuntime.recent), không dùng
//     tỉ lệ cả đời — 1 nguồn có lịch sử tốt rất dài sẽ có "quán tính": vài
//     chục lần fail dồn dập gần đây khó kéo tỉ lệ CẢ ĐỜI xuống dưới ngưỡng
//     kịp thời, khiến hệ thống tiếp tục dồn traffic vào đúng lúc nó đang
//     tệ. Cửa sổ trượt phản ứng nhanh hơn nhiều.
//
// Cả 2 lớp đều "mềm" — không bao giờ loại hẳn 1 nguồn, chỉ đẩy xuống thử
// sau, đúng triết lý xuyên suốt file này (thà thử 1 nguồn có thể tệ còn
// hơn từ chối phục vụ hoàn toàn khi mọi nguồn khác cũng đang bận/tệ).
const (
	vpnRankRecentWindow     = 20  // kích thước cửa sổ trượt (số lần thử gần nhất được nhớ) để tính tỉ lệ dùng cho xếp hạng
	vpnRankMinRecentSamples = 5   // dưới ngưỡng này trong cửa sổ: chưa đủ dữ liệu, coi như "chưa biết" — không ưu tiên cũng không bị đẩy xuống
	vpnRankGoodRate         = 0.7 // >= ngưỡng này (đủ mẫu): "đang chạy tốt", ưu tiên thử trước trong nhóm của nó
	vpnRankBadRate          = 0.4 // < ngưỡng này (đủ mẫu): "đang chạy tệ", thử sau cùng trong nhóm của nó
	vpnCapSlack             = 3   // trần mềm = trọng số cấu hình × hệ số này — phỏng đoán ban đầu, xem providerRuntime.cap

	// vpnExploreEveryN: cứ mỗi N lần gọi rankedProviders thì ĐẢO NGƯỢC thứ
	// tự trong từng nhóm (tệ thử TRƯỚC, tốt thử SAU CÙNG) thay vì luôn tốt
	// trước — thêm 2026-08-10, phát hiện thật từ stress test cùng ngày:
	// PIA-WG hút 81% tổng số lần thử trong 7 phút tải cao (275/~340), trong
	// khi CyberGhost-WG và Surfshark-WG nhận ĐÚNG 0 lần thử mới suốt cả bài
	// test dù chạy liên tục — vì 6 hãng còn lại gần như không bao giờ CÙNG
	// LÚC hết sạch lựa chọn, nên vòng lặp thử trong acquireFrom không bao
	// giờ chạm tới cuối bảng xếp hạng để "cho hãng tệ 1 cơ hội mới". Hậu
	// quả: 1 hãng bị đánh giá "tệ" dù chỉ do mẫu nhỏ/trùng hợp (ProviderStat
	// không có cơ chế hết hạn) có thể bị loại khỏi traffic GẦN NHƯ VĨNH
	// VIỄN, không có đường tự phục hồi kể cả khi nó đã sửa xong vấn đề thật.
	// Không phá cơ chế cap (lớp 1, tách under/over-cap TRƯỚC khi vào đây) —
	// thăm dò chỉ đổi thứ tự trong PHẠM VI 1 nhóm đã qua cổng an toàn đó.
	vpnExploreEveryN = 8
)

// qualityRank sắp 1 nhóm provider theo tỉ lệ thành công CỬA SỔ GẦN ĐÂY: bình
// thường tốt (đủ mẫu, tỉ lệ cao) trước, chưa rõ/ở giữa giữ nguyên thứ tự
// round-robin, tệ (đủ mẫu, tỉ lệ thấp) sau cùng — nhưng cứ mỗi
// vpnExploreEveryN lần gọi (explore=true) thì ĐẢO NGƯỢC: tệ trước, tốt sau
// cùng, để dữ liệu của nhóm "tệ" được làm mới định kỳ thay vì đóng băng
// (xem doc comment vpnExploreEveryN). Caller must hold m.mu (chỉ đọc
// runtime, không sửa).
func (m *MultiVPNProvider) qualityRankLocked(group []ProxyProvider, explore bool) []ProxyProvider {
	type scored struct {
		p    ProxyProvider
		rate float64
	}
	var good, bad []scored
	mid := make([]ProxyProvider, 0, len(group))
	for _, p := range group {
		rt := m.runtimeFor(providerName(p))
		rate, n := rt.recentRate()
		switch {
		case n < vpnRankMinRecentSamples:
			mid = append(mid, p)
		case rate >= vpnRankGoodRate:
			good = append(good, scored{p, rate})
		case rate < vpnRankBadRate:
			bad = append(bad, scored{p, rate})
		default:
			mid = append(mid, p)
		}
	}
	sort.Slice(good, func(i, j int) bool { return good[i].rate > good[j].rate })
	sort.Slice(bad, func(i, j int) bool { return bad[i].rate > bad[j].rate })

	out := make([]ProxyProvider, 0, len(group))
	if explore {
		for _, b := range bad {
			out = append(out, b.p)
		}
		out = append(out, mid...)
		for _, g := range good {
			out = append(out, g.p)
		}
		return out
	}
	for _, g := range good {
		out = append(out, g.p)
	}
	out = append(out, mid...)
	for _, b := range bad {
		out = append(out, b.p)
	}
	return out
}

// rankedProviders sắp lại thứ tự thử trong `all` (đã dedupe theo trọng số
// ở distinctProviders): trước tiên tách nguồn còn dưới trần mềm khỏi nguồn
// đã đầy (lớp 1), rồi xếp riêng từng nhóm theo tỉ lệ thành công gần đây
// (lớp 2, qualityRankLocked) — xem doc comment ngay phía trên 2 hàm này.
func (m *MultiVPNProvider) rankedProviders(all []ProxyProvider) []ProxyProvider {
	m.mu.Lock()
	m.exploreCounter++
	explore := m.exploreCounter%vpnExploreEveryN == 0
	underCap := make([]ProxyProvider, 0, len(all))
	overCap := make([]ProxyProvider, 0, len(all))
	for _, p := range all {
		rt := m.runtimeFor(providerName(p))
		if rt.active < rt.cap {
			underCap = append(underCap, p)
		} else {
			overCap = append(overCap, p)
		}
	}
	out := append(m.qualityRankLocked(underCap, explore), m.qualityRankLocked(overCap, explore)...)
	m.mu.Unlock()
	return out
}

// acquireFrom thử lần lượt từng nguồn cho tới khi có lease. Trước đây chỉ
// thử ĐÚNG 1 nguồn rồi trả lỗi thẳng — nghĩa là 1 nguồn đang kẹt (hết hạn
// mức kết nối đồng thời, hạ tầng nhà cung cấp trục trặc…) làm job fail hẳn
// dù 3 nguồn còn lại vẫn tốt. Có nhiều nguồn chính là để không phụ thuộc 1
// nguồn nào, nên phải thực sự dùng chúng khi cần.
//
// reserve()/releaseActive() bọc quanh MỖI lần thử (không chỉ khi thành
// công) — xem doc comment reserve() để biết vì sao phải tăng active TRƯỚC
// khi biết kết quả, không phải sau.
func (m *MultiVPNProvider) acquireFrom(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	var lastErr error
	for _, p := range m.rankedProviders(m.distinctProviders()) {
		if err := ctx.Err(); err != nil {
			return Lease{}, err
		}
		name := providerName(p)
		m.reserve(name)
		t0 := time.Now()
		lease, err := p.Acquire(ctx, workerID, emit)
		// errNordWGNoSlots (NordVPN-WG's hard 1-connection-per-account cap,
		// see its doc comment) means this attempt never touched a real
		// server — counting it in recordAttempt would make the account-cap
		// contention that shows up under concurrent load look identical to
		// a real bad-handshake failure, unfairly dragging down the quality
		// ranking (rankedProviders) for a provider whose actual per-server
		// picking is fine.
		if !errors.Is(err, errNordWGNoSlots) {
			m.recordAttempt(name, err == nil, time.Since(t0))
		}
		if err != nil {
			m.releaseActive(name)
			lastErr = err
			continue
		}
		lease.owner = p
		return lease, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("không có nguồn VPN nào được cấu hình")
	}
	return Lease{}, fmt.Errorf("mọi nguồn VPN đều không cấp được kết nối (lỗi cuối: %w)", lastErr)
}

func (m *MultiVPNProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	return m.acquireFrom(ctx, workerID, emit)
}

// MarkUnhealthyAndRotate trả lease cũ về ĐÚNG provider đã cấp nó (để nó
// đóng tunnel thật), rồi lấy lease mới từ vòng round-robin bình thường —
// lease mới cố tình KHÔNG ưu tiên provider cũ, vì lý do rotate thường là
// chính đường đi đó đang có vấn đề.
//
// Ghi 1 lần THẤT BẠI vào Stats()/providerRuntime.recent của provider cũ
// TRƯỚC khi rotate — sửa 2026-08-10, phát hiện thật từ log production:
// trước bản sửa này, recordAttempt() chỉ được gọi trong acquireFrom() dựa
// trên kết quả p.Acquire() (chỉ là bắt tay VPN + 1 lần GET ipify — thường
// nhanh và hầu như luôn "thành công"), KHÔNG BAO GIỜ biết được lease đó
// sau đó có sống nổi qua bài test THẬT (tải trang elevenlabs.io, hCaptcha)
// hay không — chính MarkUnhealthyAndRotate mới là nơi duy nhất biết điều
// đó (worker.go gọi hàm này đúng lúc phát hiện "mạng không ổn"). Thiếu
// dòng ghi nhận này tạo ra đúng vòng lặp luẩn quẩn quan sát được thật: 1
// nguồn bắt tay VPN nhanh/ổn định (nên Acquire() gần như luôn qua) nhưng
// phiên TTS thật qua nó hay rớt vẫn tiếp tục được xếp "tốt" và ưu tiên
// chọn lại — ranking hoàn toàn mù trước đúng loại thất bại mà cơ chế này
// được dựng ra để tránh.
func (m *MultiVPNProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	if oldLease.owner != nil {
		name := providerName(oldLease.owner)
		m.recordAttempt(name, false, 0)
		oldLease.owner.Release(workerID, oldLease)
		m.releaseActive(name)
	}
	return m.acquireFrom(ctx, workerID, emit)
}

// Release chuyển tiếp tới provider đã cấp lease. KHÔNG được để trống như
// trước: 3 provider WireGuard giữ tunnel + listener thật cho mỗi lease, bỏ
// qua Release nghĩa là tunnel không bao giờ đóng — rò rỉ dồn lại tới khi
// tài khoản VPN chạm trần số kết nối đồng thời và MỌI handshake sau đó đều
// hỏng (đã xảy ra thật, 2026-08-04: NordVPN-WG fail 40/40 lần thử liên
// tiếp ở mọi quốc gia, trong khi NordVPN-SOCKS5 cùng lúc vẫn chạy bình
// thường vì nó không tạo tunnel). Cũng giải phóng slot active tương ứng —
// bỏ qua bước này sẽ làm active chỉ tăng chứ không bao giờ giảm, cuối cùng
// mọi nguồn đều bị coi là "đầy" vĩnh viễn.
func (m *MultiVPNProvider) Release(workerID int, lease Lease) {
	if lease.owner != nil {
		lease.owner.Release(workerID, lease)
		m.releaseActive(providerName(lease.owner))
	}
}
