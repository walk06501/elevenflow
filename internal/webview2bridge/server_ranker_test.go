package webview2bridge

import "testing"

func TestServerRanker_RankedGoodThreshold(t *testing.T) {
	r := newServerRanker()

	// "a": 4 lần, 100% — dưới ngưỡng serverRankMinAttempts=5, chưa được
	// tính là tốt dù tỉ lệ hoàn hảo.
	for i := 0; i < 4; i++ {
		r.noteResult("a", true)
	}
	// "b": 5 lần, 60% — đủ mẫu nhưng dưới serverRankGoodRate=0.7.
	for i := 0; i < 3; i++ {
		r.noteResult("b", true)
	}
	for i := 0; i < 2; i++ {
		r.noteResult("b", false)
	}
	// "c": 10 lần, 80% — đủ mẫu và đạt ngưỡng.
	for i := 0; i < 8; i++ {
		r.noteResult("c", true)
	}
	for i := 0; i < 2; i++ {
		r.noteResult("c", false)
	}
	// "d": 10 lần, 100% — đủ mẫu, tỉ lệ cao hơn "c", phải xếp trước.
	for i := 0; i < 10; i++ {
		r.noteResult("d", true)
	}

	good := r.rankedGood()
	want := []string{"d", "c"}
	if len(good) != len(want) {
		t.Fatalf("rankedGood() = %v, want %v", good, want)
	}
	for i := range want {
		if good[i] != want[i] {
			t.Errorf("rankedGood()[%d] = %q, want %q (full: %v)", i, good[i], want[i], good)
		}
	}
}

func TestServerRanker_FailurePenalizesThenRecovers(t *testing.T) {
	r := newServerRanker()

	if r.isPenalized("x") {
		t.Fatal("a server with no history must not start penalized")
	}
	r.noteResult("x", false)
	if !r.isPenalized("x") {
		t.Fatal("expected 'x' to be penalized immediately after a failure")
	}
	// 1 lần thành công ngay sau đó phải xoá cooldown ngay — không bắt 1
	// server vừa mới hồi phục phải đợi hết 10 phút cũ mới được thử lại.
	r.noteResult("x", true)
	if r.isPenalized("x") {
		t.Fatal("expected 'x' to no longer be penalized after a subsequent success")
	}
}

func TestServerRanker_NoDataNeverRanked(t *testing.T) {
	r := newServerRanker()
	if good := r.rankedGood(); len(good) != 0 {
		t.Fatalf("rankedGood() on empty ranker = %v, want empty", good)
	}
}
