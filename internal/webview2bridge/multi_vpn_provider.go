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

// acquireFrom thử lần lượt từng nguồn cho tới khi có lease. Trước đây chỉ
// thử ĐÚNG 1 nguồn rồi trả lỗi thẳng — nghĩa là 1 nguồn đang kẹt (hết hạn
// mức kết nối đồng thời, hạ tầng nhà cung cấp trục trặc…) làm job fail hẳn
// dù 3 nguồn còn lại vẫn tốt. Có nhiều nguồn chính là để không phụ thuộc 1
// nguồn nào, nên phải thực sự dùng chúng khi cần.
func (m *MultiVPNProvider) acquireFrom(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	var lastErr error
	for _, p := range m.distinctProviders() {
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
