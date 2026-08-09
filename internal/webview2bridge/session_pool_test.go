package webview2bridge

import (
	"context"
	"testing"
	"time"
)

// fakeProxyProvider satisfies ProxyProvider without any real network/WebView2
// work - NewSessionPool only needs a non-nil Provider to pass validation;
// sessionLoop goroutines never call any of these methods unless they
// actually receive a job, which these tests never submit.
type fakeProxyProvider struct{}

func (fakeProxyProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	return Lease{}, nil
}
func (fakeProxyProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	return Lease{}, nil
}
func (fakeProxyProvider) Release(workerID int, lease Lease) {}

// TestBigJobReservedSessionsDefaults xác nhận công thức chia session
// big-only/small-priority đúng ở mọi biên - đặc biệt NumSessions rất nhỏ,
// nơi "chừa ít nhất 1 session mỗi bên" dễ tính sai nhất. Xem
// Config.BigJobReservedSessions doc comment cho lý do cần cả 2 sàn tối
// thiểu (job lớn không đói vì job nhỏ dồn dập, job nhỏ không đói vì dồn hết
// session vào big-only).
func TestBigJobReservedSessionsDefaults(t *testing.T) {
	cases := []struct {
		name                string
		numSessions         int
		wantBigReserved     int
		wantAtLeastOneSmall bool // NumSessions - wantBigReserved phải >= 1
	}{
		{"single session - no starvation either direction", 1, 0, true},
		{"two sessions - one each", 2, 1, true},
		{"three sessions - default fraction rounds to 1", 3, 1, true},
		{"four sessions - exactly divides", 4, 1, true},
		{"production default 20", 20, 5, true},
		{"large pool 100", 100, 25, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sp, err := NewSessionPool(SessionPoolConfig{
				NumSessions: c.numSessions,
				Provider:    fakeProxyProvider{},
				DataRoot:    t.TempDir(),
			})
			if err != nil {
				t.Fatalf("NewSessionPool failed: %v", err)
			}
			defer sp.Close()

			got := sp.cfg.BigJobReservedSessions
			if got != c.wantBigReserved {
				t.Errorf("BigJobReservedSessions = %d, want %d", got, c.wantBigReserved)
			}
			smallPriority := c.numSessions - got
			if c.wantAtLeastOneSmall && smallPriority < 1 {
				t.Errorf("only %d session(s) left in small-priority mode (numSessions=%d, reserved=%d) - small jobs would starve",
					smallPriority, c.numSessions, got)
			}
			if got < 0 || got > c.numSessions {
				t.Errorf("BigJobReservedSessions=%d out of valid range [0, %d]", got, c.numSessions)
			}
		})
	}
}

// TestBigJobReservedSessionsExplicitOverrideClamped xác nhận giá trị cấu
// hình tay quá lớn (>= NumSessions) vẫn bị kẹp lại, không dồn hết session
// vào big-only dù người vận hành lỡ đặt sai.
func TestBigJobReservedSessionsExplicitOverrideClamped(t *testing.T) {
	sp, err := NewSessionPool(SessionPoolConfig{
		NumSessions:            20,
		BigJobReservedSessions: 100, // cố tình đặt lớn hơn NumSessions
		Provider:               fakeProxyProvider{},
		DataRoot:               t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewSessionPool failed: %v", err)
	}
	defer sp.Close()

	if sp.cfg.BigJobReservedSessions >= sp.cfg.NumSessions {
		t.Errorf("BigJobReservedSessions=%d not clamped below NumSessions=%d",
			sp.cfg.BigJobReservedSessions, sp.cfg.NumSessions)
	}
}

// TestSmallJobChunkThresholdDefault xác nhận default áp dụng đúng khi
// không cấu hình, và giá trị tay được giữ nguyên khi có cấu hình.
func TestSmallJobChunkThresholdDefault(t *testing.T) {
	sp, err := NewSessionPool(SessionPoolConfig{
		NumSessions: 4,
		Provider:    fakeProxyProvider{},
		DataRoot:    t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewSessionPool failed: %v", err)
	}
	defer sp.Close()
	if sp.cfg.SmallJobChunkThreshold != defaultSmallJobChunkThreshold {
		t.Errorf("SmallJobChunkThreshold = %d, want default %d", sp.cfg.SmallJobChunkThreshold, defaultSmallJobChunkThreshold)
	}

	sp2, err := NewSessionPool(SessionPoolConfig{
		NumSessions:            4,
		SmallJobChunkThreshold: 12,
		Provider:               fakeProxyProvider{},
		DataRoot:               t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewSessionPool failed: %v", err)
	}
	defer sp2.Close()
	if sp2.cfg.SmallJobChunkThreshold != 12 {
		t.Errorf("SmallJobChunkThreshold = %d, want explicit 12", sp2.cfg.SmallJobChunkThreshold)
	}
}

// TestSubmitRoutesByChunkCount xác nhận Submit() thật sự đưa job vào đúng
// hàng đợi theo total chunk. Dựng SessionPool bằng struct literal thay vì
// NewSessionPool - KHÔNG spawn sessionLoop goroutine thật nào, nên không có
// gì nhặt job cả (channel buffer đủ lớn nên bước đẩy vào hàng không bao giờ
// block chờ chỗ trống). Test đúng phần "định tuyến", không dây vào vòng đời
// session/WebView2 thật.
func TestSubmitRoutesByChunkCount(t *testing.T) {
	sp := &SessionPool{
		cfg:       SessionPoolConfig{SmallJobChunkThreshold: defaultSmallJobChunkThreshold},
		jobs:      make(chan sessionJob, 100),
		smallJobs: make(chan sessionJob, 100),
		closed:    make(chan struct{}),
	}

	smallChunks := make([]Chunk, 3) // <= defaultSmallJobChunkThreshold (5)
	for i := range smallChunks {
		smallChunks[i] = Chunk{ID: i, Params: &TTSParams{}}
	}
	bigChunks := make([]Chunk, 8) // > defaultSmallJobChunkThreshold (5)
	for i := range bigChunks {
		bigChunks[i] = Chunk{ID: i, Params: &TTSParams{}}
	}

	// Submit() chờ kết quả sau khi đẩy xong - không có gì trả kết quả ở
	// đây (không có session thật), nên chạy nền và chỉ quan tâm bước đẩy
	// vào hàng (đồng bộ, xảy ra trước phần chờ kết quả).
	go sp.Submit(context.Background(), smallChunks, nil)
	go sp.Submit(context.Background(), bigChunks, nil)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sp.smallJobsEnqueued.Load() >= int64(len(smallChunks)) && sp.bigJobsEnqueued.Load() >= int64(len(bigChunks)) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if got := sp.smallJobsEnqueued.Load(); got != int64(len(smallChunks)) {
		t.Errorf("smallJobsEnqueued = %d, want %d", got, len(smallChunks))
	}
	if got := sp.bigJobsEnqueued.Load(); got != int64(len(bigChunks)) {
		t.Errorf("bigJobsEnqueued = %d, want %d", got, len(bigChunks))
	}
	if got := len(sp.smallJobs); got != len(smallChunks) {
		t.Errorf("smallJobs channel has %d queued, want %d", got, len(smallChunks))
	}
	if got := len(sp.jobs); got != len(bigChunks) {
		t.Errorf("jobs channel has %d queued, want %d", got, len(bigChunks))
	}
}
