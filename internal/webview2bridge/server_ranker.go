package webview2bridge

import (
	"sort"
	"sync"
	"time"
)

// Ngưỡng/cooldown dùng chung cho server_ranker — LẤY ĐÚNG con số đã chạy
// ổn định trong production từ NordVPNWireGuardProvider.rankedGoodKeysLocked
// (minAttempts=5, minSuccessRate=0.7) và noteFailure (10 phút), không đoán
// số mới cho "phiên bản dùng chung" này.
const (
	serverRankMinAttempts  = 5
	serverRankGoodRate     = 0.7
	serverRankFailCooldown = 10 * time.Minute
)

type serverRankStat struct {
	attempts, successes int
}

// serverRanker theo dõi lịch sử thành công/thất bại theo TỪNG server cụ
// thể (hostname/tên định danh riêng) BÊN TRONG 1 hãng VPN — generalize từ
// NordVPNWireGuardProvider.rankedGoodKeysLocked/keyStats/failedUntil (đã
// chạy ổn định trong production, xem doc comment gốc của 3 cái đó để biết
// đầy đủ lý do thiết kế).
//
// Thêm 2026-08-10: rà lại cả 7 provider WireGuard (grep "keyStats|
// failedUntil|rankedGood|byKey" toàn package) phát hiện CHỈ NordVPN-WG có
// bất kỳ trí nhớ nào ở tầng server — 6 provider còn lại (PIA, CyberGhost,
// Surfshark, ProtonVPN, Mullvad, IPVanish) chọn server kế tiếp bằng
// round-robin THUẦN, không nhớ gì về lần thử trước — 1 server hỏng liên
// tục bị thử lại đúng tần suất như 1 server luôn tốt. Tách phần lõi của
// Nord ra thành kiểu dùng chung này để 6 provider kia có cùng trí nhớ đó
// mà không copy/paste lại logic, thay vì để nguyên khoảng trống này (đúng
// yêu cầu "đừng bỏ lỡ gì tốt" — dữ liệu thật từng lần thử/server đã có sẵn
// từ trước, chỉ là không ai giữ lại).
//
// Server tốt/xấu có thể ĐỔI CHỖ theo thời gian (server hôm nay tốt có thể
// mai bị hãng bảo trì/quá tải) — ranker không có cơ chế "quên" chủ động
// (giống ProviderStat ở multi_vpn_provider.go, cộng dồn cả đời), nhưng
// failedUntil (cooldown 10 phút mỗi lần fail) đã đủ để 1 server mới xấu bị
// tránh THỜI GIAN GẦN, và rankedGood() chỉ xét server có sẵn ngoài cooldown
// nên tự nhiên được thử lại sau — không cần thêm cửa sổ trượt phức tạp như
// multi_vpn_provider.go's providerRuntime.recent (khác biệt có chủ đích:
// ở tầng SERVER, số lượng candidate lớn (CyberGhost ~6634) nên cooldown +
// round-robin fallback đã đủ hiệu quả; ở tầng HÃNG chỉ có 6-7 lựa chọn nên
// cần tín hiệu nhạy hơn — xem multi_vpn_provider.go).
type serverRanker struct {
	mu          sync.Mutex
	stats       map[string]*serverRankStat
	failedUntil map[string]time.Time
}

func newServerRanker() *serverRanker {
	return &serverRanker{
		stats:       map[string]*serverRankStat{},
		failedUntil: map[string]time.Time{},
	}
}

// noteResult ghi 1 kết quả thật (thành công/thất bại) cho 1 server id —
// gọi ngay sau mỗi lần tryOne() trả về, giống hệt Nord's noteKeyResult.
func (r *serverRanker) noteResult(id string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, exists := r.stats[id]
	if !exists {
		st = &serverRankStat{}
		r.stats[id] = st
	}
	st.attempts++
	if ok {
		st.successes++
	}
	if !ok {
		r.failedUntil[id] = time.Now().Add(serverRankFailCooldown)
	} else {
		delete(r.failedUntil, id)
	}
}

// rankedGood trả về mọi server id đã đủ dữ liệu (>=serverRankMinAttempts)
// và đạt ngưỡng đáng tin (>=serverRankGoodRate), xếp tỉ lệ cao xuống thấp.
// Id CHƯA đủ dữ liệu không nằm trong danh sách này (không được ưu tiên,
// cũng không bị phạt) — đây chính là cách 1 server mới/ít dữ liệu được
// thăm dò tự nhiên qua round-robin bình thường thay vì bị nhóm "tốt" che
// mất, y hệt lý do NordVPN-WG's rankedGoodKeysLocked.
func (r *serverRanker) rankedGood() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	type scored struct {
		id   string
		rate float64
	}
	var good []scored
	for id, st := range r.stats {
		if st.attempts < serverRankMinAttempts {
			continue
		}
		rate := float64(st.successes) / float64(st.attempts)
		if rate >= serverRankGoodRate {
			good = append(good, scored{id, rate})
		}
	}
	sort.Slice(good, func(i, j int) bool { return good[i].rate > good[j].rate })
	out := make([]string, len(good))
	for i, g := range good {
		out[i] = g.id
	}
	return out
}

// isPenalized báo 1 id có đang trong thời gian cooldown sau lần fail gần
// nhất không — tự dọn mục đã hết hạn luôn (như Nord's failedUntil check).
func (r *serverRanker) isPenalized(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	until, ok := r.failedUntil[id]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(r.failedUntil, id)
		return false
	}
	return true
}
