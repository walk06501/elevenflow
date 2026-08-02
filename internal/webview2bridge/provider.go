package webview2bridge

import (
	"context"
	"sync"
	"time"

	"elevenflow/internal/proxyserver"
)

// ProxyProvider trừu tượng hóa nguồn cung cấp proxy URL cho từng worker.
//
// Hôm nay (1 proxy "current" trên server, auto-rotate ~60s): N worker chia sẻ
// cùng 1 IP. Khi 1 worker hit 401 → coalesce rotation request, cả N worker
// nhận IP mới cùng lúc.
//
// Tương lai (N proxy độc lập trên DB): mỗi worker lease 1 proxy slot riêng;
// 401 trên slot A không ảnh hưởng slot B. Implement bằng struct mới thoả
// interface này, swap qua app.go.
type ProxyProvider interface {
	// Acquire trả về proxy URL cho worker. Block nếu chưa có proxy
	// (lần đầu, hoặc đang đợi rotation hoàn tất).
	Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error)

	// MarkUnhealthyAndRotate báo proxy hiện tại đã bị ElevenLabs flag
	// (401 unusual_activity). Trả về lease mới sau khi server rotate IP.
	// Coalesce: nhiều worker gọi gần như đồng thời chỉ trigger 1 rotation
	// duy nhất, các worker khác nhận lease mới khi rotation xong.
	MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error)

	// Release báo worker không còn dùng lease (kết thúc batch / shutdown).
	Release(workerID int, lease Lease)
}

// Lease là handle proxy đang gán cho 1 worker. Provider có thể attach
// metadata (slot ID, expire time…) ngoài URL.
type Lease struct {
	URL        string
	AcquiredAt time.Time
	// Generation tăng mỗi lần rotation toàn cục, dùng để detect "lease cũ".
	Generation int64
}

// Equal so sánh URL của 2 lease — quyết định rotation đã xảy ra chưa.
func (l Lease) Equal(other Lease) bool { return l.URL == other.URL }

// SharedCurrentProvider wrap proxyserver.Client (1 IP "current" share toàn pool).
// Đáp ứng API hiện tại của ElevenFlow Vercel server.
type SharedCurrentProvider struct {
	client *proxyserver.Client

	mu         sync.Mutex
	current    Lease
	generation int64
}

func NewSharedCurrentProvider(client *proxyserver.Client) *SharedCurrentProvider {
	return &SharedCurrentProvider{client: client}
}

func (p *SharedCurrentProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	p.mu.Lock()
	cur := p.current
	p.mu.Unlock()

	if cur.URL != "" {
		return cur, nil
	}
	url, err := p.client.Current(ctx)
	if err != nil {
		return Lease{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current.URL == "" {
		p.generation++
		p.current = Lease{URL: url, AcquiredAt: time.Now(), Generation: p.generation}
	}
	return p.current, nil
}

func (p *SharedCurrentProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	if emit == nil {
		emit = func(string) {}
	}
	// Coalesce: GIỮ mutex suốt cả lúc poll server. Worker thứ 2 block ở Lock(),
	// khi worker 1 xong + đã update p.current, worker 2 mới acquire mutex →
	// thấy current.URL != oldLease → return ngay, KHÔNG poll lại server.
	// (Bug cũ: unlock trước RotateWithWait → 2 worker poll song song, server
	// gửi countdown 60s × 2 lần → đợi gấp đôi.)
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.current.URL != "" && !p.current.Equal(oldLease) {
		emit("Đã có kết nối mới.")
		return p.current, nil
	}

	url, err := p.client.RotateWithWait(ctx, emit)
	if err != nil {
		return Lease{}, err
	}
	p.generation++
	p.current = Lease{URL: url, AcquiredAt: time.Now(), Generation: p.generation}
	return p.current, nil
}

func (p *SharedCurrentProvider) Release(workerID int, lease Lease) {
	// No-op: shared current không cần release per-worker.
}
