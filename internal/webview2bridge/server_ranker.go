package webview2bridge

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
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

	// serverRankBanCooldown: khi ElevenLabs tự trả 401
	// "detected_unusual_activity" (kind=FailureBan) trên 1 lease, id server
	// ĐANG DÙNG lúc đó bị loại khỏi vòng xoay 24h — tách khỏi failedUntil
	// (10 phút, dành cho lỗi bắt tay/kết nối thông thường, không phải tín
	// hiệu thật từ chính hãng đang dùng) vì đây là bằng chứng THẬT, đáng
	// tin hơn hẳn 1 lần thất bại đơn lẻ. Thêm 2026-08-19 theo yêu cầu
	// operator, áp dụng đồng loạt cho mọi provider dùng serverRanker (trước
	// đó chỉ NordVPN-WG có, bespoke) — xem noteBan.
	serverRankBanCooldown = 24 * time.Hour
)

// serverRankNetworkLadder: cooldown leo thang cho lỗi "mạng không ổn"
// (kind=FailureNetwork, errTransient ở worker.go) — KHÁC ban ở trên (không
// phải tín hiệu ElevenLabs tự flag, chỉ là 1 request cụ thể gặp lỗi mạng/
// timeout/5xx/429) nên bắt đầu nhẹ hơn nhiều, chỉ leo thang nếu CÙNG 1
// server lặp lại lỗi này ở NHIỀU lease khác nhau (mỗi lần escalate là 1
// lần MarkUnhealthyAndRotate mới, không phải retry nội bộ 1 request). Nấc
// cuối lặp lại cho các lần lỗi tiếp theo thay vì tăng vô hạn. Reset về đáy
// (xoá khỏi map) ngay khi server này phục vụ trót lọt 1 chunk — xem
// noteChunkOK.
var serverRankNetworkLadder = []time.Duration{
	20 * time.Minute,
	1 * time.Hour,
	6 * time.Hour,
	12 * time.Hour,
	23 * time.Hour,
}

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
type netBackoffState struct {
	until time.Time
	level int
}

type serverRanker struct {
	mu          sync.Mutex
	stats       map[string]*serverRankStat
	failedUntil map[string]time.Time
	// bannedUntil/netPenalty: xem serverRankBanCooldown/
	// serverRankNetworkLadder ở trên. Lưu đĩa (persistPath) — KHÁC
	// failedUntil/stats (chỉ nhớ trong phiên chạy, giống lý do gốc trong
	// doc comment của serverRanker: 1 server tốt/xấu có thể đổi chỗ, không
	// đáng lưu lâu dài) vì ban/network-penalty là tín hiệu đáng tin hơn,
	// xứng đáng sống qua restart.
	bannedUntil map[string]time.Time
	netPenalty  map[string]*netBackoffState
	// persistPath: "" tắt hẳn việc đọc/ghi đĩa (dùng cho test) — mọi
	// provider thật phải truyền 1 key ổn định (xem newServerRanker).
	persistPath string
}

// serverRankerPersistPath: tên file ổn định theo persistKey (thường là
// tên hãng, có thể kèm theo định danh account nếu provider đó có nhiều
// account) — băm qua sha256 để không lộ token/credential thật ra tên file
// nếu persistKey vô tình chứa nó, giống hệt quy ước nordWGDiscoveryPath.
func serverRankerPersistPath(persistKey string) string {
	sum := sha256.Sum256([]byte(persistKey))
	return filepath.Join(".", fmt.Sprintf("server_ranker_penalties_%x.json", sum[:6]))
}

type serverRankerPersisted struct {
	Bans []struct {
		ID    string    `json:"id"`
		Until time.Time `json:"until"`
	} `json:"bans"`
	NetPenalties []struct {
		ID    string    `json:"id"`
		Until time.Time `json:"until"`
		Level int       `json:"level"`
	} `json:"network_penalties"`
}

// newServerRanker: persistKey nên là 1 chuỗi ổn định, riêng cho từng
// provider/account (vd "surfshark", "pia-wg:"+username) — dùng để đặt tên
// file lưu ban/network-penalty (xem serverRankerPersistPath). Truyền ""
// để tắt hẳn persistence (chỉ dùng trong test).
func newServerRanker(persistKey string) *serverRanker {
	r := &serverRanker{
		stats:       map[string]*serverRankStat{},
		failedUntil: map[string]time.Time{},
		bannedUntil: map[string]time.Time{},
		netPenalty:  map[string]*netBackoffState{},
		persistPath: "",
	}
	if persistKey == "" {
		return r
	}
	r.persistPath = serverRankerPersistPath(persistKey)
	data, err := os.ReadFile(r.persistPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[server_ranker] Warning: failed to load penalty cache %s: %v", r.persistPath, err)
		}
		return r
	}
	var saved serverRankerPersisted
	if err := json.Unmarshal(data, &saved); err != nil {
		log.Printf("[server_ranker] Warning: failed to parse penalty cache %s: %v", r.persistPath, err)
		return r
	}
	now := time.Now()
	for _, b := range saved.Bans {
		if b.ID != "" && now.Before(b.Until) {
			r.bannedUntil[b.ID] = b.Until
		}
	}
	for _, n := range saved.NetPenalties {
		if n.ID != "" && now.Before(n.Until) {
			r.netPenalty[n.ID] = &netBackoffState{until: n.Until, level: n.Level}
		}
	}
	if len(r.bannedUntil) > 0 || len(r.netPenalty) > 0 {
		log.Printf("[server_ranker] Loaded %d banned + %d network-penalised server(s) from %s", len(r.bannedUntil), len(r.netPenalty), r.persistPath)
	}
	return r
}

// persistLocked ghi lại toàn bộ bannedUntil+netPenalty hiện tại — gọi sau
// mỗi lần đổi (ban mới, escalate, hoặc reset). Đây đều là đường lỗi hiếm
// (không phải per-chunk hot path) nên ghi cả file mỗi lần là đơn giản và
// an toàn hơn hẳn 1 cơ chế diff/append, giống hệt saveNordWGDiscovered.
// Caller phải giữ r.mu khi gọi hàm build snapshot, nhưng bản thân việc ghi
// file chạy SAU khi đã nhả lock (I/O không nên giữ mutex).
func (r *serverRanker) persist() {
	if r.persistPath == "" {
		return
	}
	r.mu.Lock()
	var saved serverRankerPersisted
	for id, until := range r.bannedUntil {
		saved.Bans = append(saved.Bans, struct {
			ID    string    `json:"id"`
			Until time.Time `json:"until"`
		}{ID: id, Until: until})
	}
	for id, st := range r.netPenalty {
		saved.NetPenalties = append(saved.NetPenalties, struct {
			ID    string    `json:"id"`
			Until time.Time `json:"until"`
			Level int       `json:"level"`
		}{ID: id, Until: st.until, Level: st.level})
	}
	r.mu.Unlock()
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		log.Printf("[server_ranker] Warning: failed to encode penalty cache: %v", err)
		return
	}
	if err := os.WriteFile(r.persistPath, data, 0o600); err != nil {
		log.Printf("[server_ranker] Warning: failed to write penalty cache %s: %v", r.persistPath, err)
	}
}

// noteBan đánh dấu id bị ban 24h — gọi khi kind==FailureBan (ElevenLabs tự
// flag unusual activity trên lease đang dùng id này).
func (r *serverRanker) noteBan(id string) {
	r.mu.Lock()
	r.bannedUntil[id] = time.Now().Add(serverRankBanCooldown)
	r.mu.Unlock()
	r.persist()
}

// noteNetworkIssue leo id lên 1 nấc trong serverRankNetworkLadder — gọi
// khi kind==FailureNetwork (lỗi mạng/timeout/5xx/429 ở worker.go).
func (r *serverRanker) noteNetworkIssue(id string) {
	r.mu.Lock()
	st, ok := r.netPenalty[id]
	if !ok {
		st = &netBackoffState{level: -1}
		r.netPenalty[id] = st
	}
	if st.level < len(serverRankNetworkLadder)-1 {
		st.level++
	}
	st.until = time.Now().Add(serverRankNetworkLadder[st.level])
	r.mu.Unlock()
	r.persist()
}

// noteChunkOK xoá hẳn nấc phạt mạng hiện tại của id (nếu có) — gọi ngay
// khi 1 chunk hoàn tất trót lọt trên lease đang dùng id này, để lần lỗi
// mạng KẾ TIẾP (nếu có) bắt đầu lại từ đáy thang thay vì tiếp tục leo từ
// nấc cũ. Không đụng bannedUntil (ban 24h không reset theo thành công —
// tín hiệu unusual-activity không liên quan gì tới việc 1 lease sau đó có
// chạy trơn tru hay không).
func (r *serverRanker) noteChunkOK(id string) {
	r.mu.Lock()
	_, had := r.netPenalty[id]
	if had {
		delete(r.netPenalty, id)
	}
	r.mu.Unlock()
	if had {
		r.persist()
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
			// Sort key is the Wilson lower bound, not the raw rate, so a
			// lucky 5/5 doesn't permanently outrank a proven 190/200 — see
			// rank_confidence.go. Eligibility (the >= serverRankGoodRate
			// gate above) still uses the raw rate, unchanged.
			good = append(good, scored{id, wilsonLowerBound(st.successes, st.attempts)})
		}
	}
	sort.Slice(good, func(i, j int) bool { return good[i].rate > good[j].rate })
	out := make([]string, len(good))
	for i, g := range good {
		out[i] = g.id
	}
	return out
}

// isPenalized báo 1 id có đang bị loại khỏi vòng xoay không — gộp cả 3
// nguồn phạt (failedUntil 10 phút, bannedUntil 24h, netPenalty leo thang),
// tự dọn mục đã hết hạn luôn ở mỗi nguồn (như Nord's failedUntil check).
func (r *serverRanker) isPenalized(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	penalised := false
	if until, ok := r.failedUntil[id]; ok {
		if now.After(until) {
			delete(r.failedUntil, id)
		} else {
			penalised = true
		}
	}
	if until, ok := r.bannedUntil[id]; ok {
		if now.After(until) {
			delete(r.bannedUntil, id)
		} else {
			penalised = true
		}
	}
	if st, ok := r.netPenalty[id]; ok {
		if now.After(st.until) {
			delete(r.netPenalty, id)
		} else {
			penalised = true
		}
	}
	return penalised
}
