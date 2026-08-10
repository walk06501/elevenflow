package webview2bridge

import (
	"context"
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
// /health directly.
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
}

func NewMultiVPNProvider(providers ...ProxyProvider) *MultiVPNProvider {
	m := &MultiVPNProvider{providers: providers, stats: map[string]*ProviderStat{}}
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
// worst-success-rate-first — the point of glancing at this line is
// spotting a degrading source, so the one most worth looking at belongs
// at the front, not buried after five healthy ones in alphabetical order.
func (m *MultiVPNProvider) statsLogger() {
	t := time.NewTicker(vpnStatsLogInterval)
	defer t.Stop()
	for range t.C {
		snap := m.Stats()
		if len(snap) == 0 {
			continue
		}
		type row struct {
			name string
			st   ProviderStat
			rate float64
		}
		rows := make([]row, 0, len(snap))
		for name, st := range snap {
			rate := 1.0
			if st.Attempts > 0 {
				rate = float64(st.Successes) / float64(st.Attempts)
			}
			rows = append(rows, row{name, st, rate})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].rate < rows[j].rate })

		parts := make([]string, 0, len(rows))
		for _, r := range rows {
			avgMs := int64(0)
			if r.st.Successes > 0 {
				avgMs = r.st.TotalMs / r.st.Successes
			}
			parts = append(parts, fmt.Sprintf(
				"%s: %d/%d (%.0f%%) tb=%.1fs max=%.1fs",
				r.name, r.st.Successes, r.st.Attempts, r.rate*100,
				float64(avgMs)/1000, float64(r.st.MaxMs)/1000,
			))
		}
		log.Printf("[vpn-stats] %s", strings.Join(parts, " | "))
	}
}

// Ngưỡng xếp hạng provider theo lịch sử thật (Stats) — y hệt ngưỡng
// NordVPNWireGuardProvider.rankedGoodKeysLocked dùng cho các key con của
// riêng nó, áp lên 1 tầng cao hơn: xếp hạng GIỮA CÁC HÃNG thay vì giữa các
// server/key trong cùng 1 hãng. Thêm 2026-08-10 sau khi operator hỏi có
// cách nào biết trước 1 lease có ổn không trước khi giao cho worker thật —
// câu trả lời đã tồn tại trong chính codebase này (worker.go's doc comment
// về navTimeout/stallTimeout): 1 lần GET/handshake nhẹ lúc Acquire() không
// đủ chứng minh tunnel chịu nổi tải trang thật, nên KHÔNG thêm 1 bài test
// nhẹ mới (dễ cho qua nhầm/loại nhầm so với tải trang thật). Thay vào đó
// tận dụng đúng dữ liệu THẬT đã tích luỹ từ chính các lần thử thật
// (navTimeout/stallTimeout/HTTP lỗi đều đã phản ánh vào recordAttempt) để
// đổi THỨ TỰ thử giữa các hãng — hãng đang chạy tốt được thử trước, hãng
// đang chạy tệ bị đẩy xuống cuối, nhưng KHÔNG hãng nào bị loại hẳn (đúng
// triết lý xuyên suốt file này: không phụ thuộc/loại bỏ vĩnh viễn 1 nguồn).
const (
	vpnRankMinAttempts = 5   // dưới ngưỡng này: chưa đủ dữ liệu, coi như "chưa biết" — không được thử sớm hơn (may mắn vài lần đầu không đủ), cũng không bị đẩy xuống cuối
	vpnRankGoodRate    = 0.7 // >= ngưỡng này (đủ dữ liệu): "đang chạy tốt", ưu tiên thử trước
	vpnRankBadRate     = 0.4 // < ngưỡng này (đủ dữ liệu): "đang chạy tệ", đẩy xuống thử cuối cùng, không loại hẳn
)

// rankedProviders sắp lại thứ tự thử trong `all` (đã dedupe theo trọng số ở
// distinctProviders) thành 3 nhóm, mỗi nhóm giữ nguyên thứ tự round-robin
// nội bộ trừ 2 nhóm đầu/cuối được sắp theo tỉ lệ thành công thật:
//  1. "Tốt" (đủ mẫu, tỉ lệ >= vpnRankGoodRate) — thử trước, tỉ lệ cao nhất
//     trước tiên.
//  2. "Chưa rõ" (chưa đủ mẫu, hoặc đủ mẫu nhưng ở khoảng giữa) — giữ đúng
//     thứ tự round-robin bình thường, đây cũng chính là cách 1 hãng mới/ít
//     dữ liệu được thăm dò tự nhiên thay vì bị cả 2 nhóm kia che mất.
//  3. "Tệ" (đủ mẫu, tỉ lệ < vpnRankBadRate) — thử cuối cùng, vẫn được thử
//     khi 2 nhóm kia đều hết chứ không bị loại hẳn.
func (m *MultiVPNProvider) rankedProviders(all []ProxyProvider) []ProxyProvider {
	snap := m.Stats()
	type scored struct {
		p    ProxyProvider
		rate float64
	}
	var good, bad []scored
	mid := make([]ProxyProvider, 0, len(all))
	for _, p := range all {
		st, ok := snap[providerName(p)]
		if !ok || st.Attempts < vpnRankMinAttempts {
			mid = append(mid, p)
			continue
		}
		rate := float64(st.Successes) / float64(st.Attempts)
		switch {
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

	out := make([]ProxyProvider, 0, len(all))
	for _, g := range good {
		out = append(out, g.p)
	}
	out = append(out, mid...)
	for _, b := range bad {
		out = append(out, b.p)
	}
	return out
}

// acquireFrom thử lần lượt từng nguồn cho tới khi có lease. Trước đây chỉ
// thử ĐÚNG 1 nguồn rồi trả lỗi thẳng — nghĩa là 1 nguồn đang kẹt (hết hạn
// mức kết nối đồng thời, hạ tầng nhà cung cấp trục trặc…) làm job fail hẳn
// dù 3 nguồn còn lại vẫn tốt. Có nhiều nguồn chính là để không phụ thuộc 1
// nguồn nào, nên phải thực sự dùng chúng khi cần.
func (m *MultiVPNProvider) acquireFrom(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	var lastErr error
	for _, p := range m.rankedProviders(m.distinctProviders()) {
		if err := ctx.Err(); err != nil {
			return Lease{}, err
		}
		name := providerName(p)
		t0 := time.Now()
		lease, err := p.Acquire(ctx, workerID, emit)
		m.recordAttempt(name, err == nil, time.Since(t0))
		if err != nil {
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
func (m *MultiVPNProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	if oldLease.owner != nil {
		oldLease.owner.Release(workerID, oldLease)
	}
	return m.acquireFrom(ctx, workerID, emit)
}

// Release chuyển tiếp tới provider đã cấp lease. KHÔNG được để trống như
// trước: 3 provider WireGuard giữ tunnel + listener thật cho mỗi lease, bỏ
// qua Release nghĩa là tunnel không bao giờ đóng — rò rỉ dồn lại tới khi
// tài khoản VPN chạm trần số kết nối đồng thời và MỌI handshake sau đó đều
// hỏng (đã xảy ra thật, 2026-08-04: NordVPN-WG fail 40/40 lần thử liên
// tiếp ở mọi quốc gia, trong khi NordVPN-SOCKS5 cùng lúc vẫn chạy bình
// thường vì nó không tạo tunnel).
func (m *MultiVPNProvider) Release(workerID int, lease Lease) {
	if lease.owner != nil {
		lease.owner.Release(workerID, lease)
	}
}
