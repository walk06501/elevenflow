package webview2bridge

import (
	"context"
	"testing"
)

// fakeVPNProvider: chỉ đủ để thoả ProxyProvider+named cho test, không mở
// tunnel thật gì cả.
type fakeVPNProvider struct{ name string }

func (f *fakeVPNProvider) Name() string { return f.name }
func (f *fakeVPNProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	return Lease{}, nil
}
func (f *fakeVPNProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	return Lease{}, nil
}
func (f *fakeVPNProvider) Release(workerID int, lease Lease) {}

func newTestMultiVPN(names ...string) (*MultiVPNProvider, []ProxyProvider) {
	providers := make([]ProxyProvider, len(names))
	for i, n := range names {
		providers[i] = &fakeVPNProvider{name: n}
	}
	// Không dùng NewMultiVPNProvider (nó spawn statsLogger goroutine không
	// cần cho test thuần logic) — dựng tay struct với đúng field cần.
	weight := map[string]int{}
	for _, p := range providers {
		weight[providerName(p)]++
	}
	runtime := make(map[string]*providerRuntime, len(weight))
	for name, w := range weight {
		runtime[name] = &providerRuntime{cap: newProviderCap(w)}
	}
	return &MultiVPNProvider{providers: providers, stats: map[string]*ProviderStat{}, runtime: runtime}, providers
}

func TestQualityRankLocked_GoodFirstBadLast(t *testing.T) {
	m, providers := newTestMultiVPN("good", "mid", "bad", "unknown")

	// "good": 8/10 = 80% >= vpnRankGoodRate, đủ mẫu.
	for i := 0; i < 8; i++ {
		m.runtime["good"].pushRecent(true)
	}
	for i := 0; i < 2; i++ {
		m.runtime["good"].pushRecent(false)
	}
	// "bad": 1/10 = 10% < vpnRankBadRate, đủ mẫu.
	for i := 0; i < 1; i++ {
		m.runtime["bad"].pushRecent(true)
	}
	for i := 0; i < 9; i++ {
		m.runtime["bad"].pushRecent(false)
	}
	// "mid": 5/10 = 50%, ở giữa 2 ngưỡng, đủ mẫu -> vẫn coi là "chưa rõ"/giữ nguyên vị trí.
	for i := 0; i < 5; i++ {
		m.runtime["mid"].pushRecent(true)
	}
	for i := 0; i < 5; i++ {
		m.runtime["mid"].pushRecent(false)
	}
	// "unknown": chưa có mẫu nào -> giữ nguyên vị trí.

	m.mu.Lock()
	out := m.qualityRankLocked(providers, false)
	m.mu.Unlock()

	if len(out) != 4 {
		t.Fatalf("expected 4 providers back, got %d", len(out))
	}
	if providerName(out[0]) != "good" {
		t.Errorf("expected 'good' first, got %q", providerName(out[0]))
	}
	if providerName(out[len(out)-1]) != "bad" {
		t.Errorf("expected 'bad' last, got %q", providerName(out[len(out)-1]))
	}
	// mid/unknown phải nằm GIỮA good và bad, đúng thứ tự round-robin gốc
	// (mid trước unknown, vì providers slice truyền vào theo thứ tự đó).
	if providerName(out[1]) != "mid" || providerName(out[2]) != "unknown" {
		t.Errorf("expected [mid, unknown] in the middle, got [%s, %s]", providerName(out[1]), providerName(out[2]))
	}
}

// TestQualityRankLocked_Explore khoá lại hành vi "thăm dò định kỳ" mới thêm
// 2026-08-10: khi explore=true, thứ tự phải ĐẢO NGƯỢC (tệ trước, tốt sau
// cùng) — đây chính là cơ chế chống đóng băng dữ liệu phát hiện từ stress
// test thật (CyberGhost/Surfshark nhận 0 lần thử mới suốt 7 phút tải cao).
func TestQualityRankLocked_Explore(t *testing.T) {
	m, providers := newTestMultiVPN("good", "bad")
	for i := 0; i < 8; i++ {
		m.runtime["good"].pushRecent(true)
	}
	for i := 0; i < 2; i++ {
		m.runtime["good"].pushRecent(false)
	}
	for i := 0; i < 1; i++ {
		m.runtime["bad"].pushRecent(true)
	}
	for i := 0; i < 9; i++ {
		m.runtime["bad"].pushRecent(false)
	}

	m.mu.Lock()
	normal := m.qualityRankLocked(providers, false)
	explore := m.qualityRankLocked(providers, true)
	m.mu.Unlock()

	if providerName(normal[0]) != "good" || providerName(normal[1]) != "bad" {
		t.Fatalf("normal order = %v, want [good, bad]", []string{providerName(normal[0]), providerName(normal[1])})
	}
	if providerName(explore[0]) != "bad" || providerName(explore[1]) != "good" {
		t.Fatalf("explore order = %v, want [bad, good] (reversed)", []string{providerName(explore[0]), providerName(explore[1])})
	}
}

// TestRankedProviders_ExploreFiresEveryN xác nhận rankedProviders() thật sự
// đảo ngược đúng 1 lần trong mỗi vpnExploreEveryN lần gọi liên tiếp — không
// phải logic đúng trong qualityRankLocked nhưng không bao giờ được kích
// hoạt từ caller thật.
func TestRankedProviders_ExploreFiresEveryN(t *testing.T) {
	m, _ := newTestMultiVPN("good", "bad")
	for i := 0; i < 8; i++ {
		m.runtime["good"].pushRecent(true)
	}
	for i := 0; i < 2; i++ {
		m.runtime["good"].pushRecent(false)
	}
	for i := 0; i < 1; i++ {
		m.runtime["bad"].pushRecent(true)
	}
	for i := 0; i < 9; i++ {
		m.runtime["bad"].pushRecent(false)
	}

	exploreHits := 0
	for i := 0; i < vpnExploreEveryN*3; i++ {
		all := m.distinctProviders()
		out := m.rankedProviders(all)
		if providerName(out[0]) == "bad" {
			exploreHits++
		}
	}
	if exploreHits != 3 {
		t.Fatalf("exploreHits = %d over %d calls, want exactly 3 (1 per %d-call cycle)", exploreHits, vpnExploreEveryN*3, vpnExploreEveryN)
	}
}

func TestQualityRankLocked_NotEnoughSamplesNeverRanked(t *testing.T) {
	m, providers := newTestMultiVPN("almost-good")
	// 4 mẫu, 100% thành công — dưới ngưỡng vpnRankMinRecentSamples=5, không
	// được coi là "tốt" dù tỉ lệ hoàn hảo (đúng lý do NordVPN's
	// rankedGoodKeysLocked ngăn vài lần may mắn đầu tiên đẩy 1 nguồn tầm
	// thường lên sớm).
	for i := 0; i < 4; i++ {
		m.runtime["almost-good"].pushRecent(true)
	}
	m.mu.Lock()
	rate, n := m.runtime["almost-good"].recentRate()
	out := m.qualityRankLocked(providers, false)
	m.mu.Unlock()
	if n != 4 || rate != 1.0 {
		t.Fatalf("sanity check failed: rate=%v n=%v", rate, n)
	}
	if len(out) != 1 || providerName(out[0]) != "almost-good" {
		t.Fatalf("expected the single under-sampled provider to still be returned, got %v", out)
	}
}

func TestRankedProviders_OverCapPushedLast(t *testing.T) {
	m, _ := newTestMultiVPN("full", "spare")
	// "full" đang đầy trần (active >= cap), dù chưa có dữ liệu chất lượng
	// gì — vẫn phải bị đẩy xuống sau "spare" (còn chỗ).
	m.runtime["full"].active = m.runtime["full"].cap

	all := m.distinctProviders()
	out := m.rankedProviders(all)
	if len(out) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(out))
	}
	if providerName(out[0]) != "spare" {
		t.Errorf("expected 'spare' (under cap) first, got %q", providerName(out[0]))
	}
	if providerName(out[1]) != "full" {
		t.Errorf("expected 'full' (over cap) last, got %q", providerName(out[1]))
	}
}

func TestReserveAndReleaseActive(t *testing.T) {
	m, _ := newTestMultiVPN("x")

	m.reserve("x")
	m.reserve("x")
	if got := m.runtime["x"].active; got != 2 {
		t.Fatalf("active after 2 reserves = %d, want 2", got)
	}
	m.releaseActive("x")
	if got := m.runtime["x"].active; got != 1 {
		t.Fatalf("active after 1 release = %d, want 1", got)
	}
	// Không được xuống âm dù release nhiều hơn reserve — bug loại này sẽ
	// làm 1 nguồn bị coi là "còn thừa chỗ" mãi mãi kể cả khi đang quá tải
	// thật, ngược hẳn mục đích của cơ chế cap.
	m.releaseActive("x")
	m.releaseActive("x")
	if got := m.runtime["x"].active; got != 0 {
		t.Fatalf("active after over-releasing = %d, want floored at 0", got)
	}
}

func TestPushRecentWindowBounded(t *testing.T) {
	pr := &providerRuntime{}
	for i := 0; i < vpnRankRecentWindow+10; i++ {
		pr.pushRecent(true)
	}
	if len(pr.recent) != vpnRankRecentWindow {
		t.Fatalf("recent window len = %d, want capped at %d", len(pr.recent), vpnRankRecentWindow)
	}
}

// TestMarkUnhealthyAndRotate_RecordsFailureAgainstOldProvider khoá lại
// đúng lỗi thật phát hiện 2026-08-10 từ log production: trước bản sửa,
// MarkUnhealthyAndRotate (worker.go gọi đúng lúc "mạng không ổn" — nghĩa
// là lease đã qua được Acquire() nhưng thất bại ở bài test THẬT, tải
// trang) không hề ghi nhận gì vào Stats()/recent — khiến 1 nguồn bắt tay
// VPN nhanh nhưng hay rớt phiên thật vẫn tiếp tục được xếp "tốt" và ưu
// tiên chọn lại, một vòng luẩn quẩn quan sát được thật trên VPS.
func TestMarkUnhealthyAndRotate_RecordsFailureAgainstOldProvider(t *testing.T) {
	m, _ := newTestMultiVPN("flaky")
	owner := &fakeVPNProvider{name: "flaky"}
	oldLease := Lease{owner: owner, Generation: 1}

	// MarkUnhealthyAndRotate tự nó gọi tiếp acquireFrom() để lấy lease mới
	// (đây là hành vi có từ trước, không phải phần đang test) — với chỉ 1
	// provider "flaky" cấu hình, acquireFrom() sẽ acquire lại đúng "flaky"
	// và ghi thêm 1 THÀNH CÔNG. Nên sau lệnh gọi đầy đủ: 2 attempts (1 thất
	// bại từ chính rotate đang test + 1 thành công từ acquire kế tiếp).
	if _, err := m.MarkUnhealthyAndRotate(context.Background(), 0, oldLease, nil); err != nil {
		t.Fatalf("MarkUnhealthyAndRotate returned unexpected error: %v", err)
	}

	st, ok := m.Stats()["flaky"]
	if !ok {
		t.Fatal("expected a Stats() entry for \"flaky\" after MarkUnhealthyAndRotate")
	}
	if st.Attempts != 2 || st.Successes != 1 {
		t.Fatalf("Stats()[\"flaky\"] = %+v, want 2 attempts / 1 success (1 failure recorded for the rotate itself, 1 success from the follow-up acquire)", st)
	}

	m.mu.Lock()
	recent := append([]bool(nil), m.runtime["flaky"].recent...)
	m.mu.Unlock()
	if len(recent) != 2 || recent[0] != false || recent[1] != true {
		t.Fatalf("recent window = %v, want [false, true] — the rotate failure must land in the recency window BEFORE the follow-up success, in order", recent)
	}
}

func TestNewProviderCap_MinimumFloor(t *testing.T) {
	if got := newProviderCap(0); got != vpnCapSlack {
		t.Errorf("newProviderCap(0) = %d, want floor of weight=1 * slack = %d", got, vpnCapSlack)
	}
	if got := newProviderCap(6); got != 6*vpnCapSlack {
		t.Errorf("newProviderCap(6) = %d, want %d", got, 6*vpnCapSlack)
	}
}
