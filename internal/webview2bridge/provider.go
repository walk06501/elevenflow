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
	// (401 unusual_activity) HOẶC gặp lỗi mạng/tunnel — kind phân biệt 2
	// trường hợp đó (xem FailureKind). Trả về lease mới sau khi server
	// rotate IP. Coalesce: nhiều worker gọi gần như đồng thời chỉ trigger 1
	// rotation duy nhất, các worker khác nhận lease mới khi rotation xong.
	//
	// kind được thêm 2026-08-19: worker.go đã tự phân loại 2 loại lỗi này
	// từ trước (BanRotates/NetworkRotates), nhưng cả 2 đều gọi
	// MarkUnhealthyAndRotate giống hệt nhau nên phân loại đó bị vứt bỏ
	// ngay khi qua khỏi worker.go — MultiVPNProvider.recordAttempt ghi
	// nhận 1 "thất bại" chung, không biết là IP bị cấm (đổi IP là đủ, nguồn
	// VPN không có lỗi) hay tunnel/mạng thật sự tệ (nên giảm ưu tiên
	// nguồn). Chỉ MultiVPNProvider thực sự DÙNG tham số này (tách riêng 2
	// bộ đếm trong ProviderStat, xem recordAttempt) — mọi provider khác chỉ
	// nhận rồi bỏ qua, không đổi hành vi rotate/chọn server nội bộ của
	// chúng.
	MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, kind FailureKind, emit func(string)) (Lease, error)

	// Release báo worker không còn dùng lease (kết thúc batch / shutdown).
	Release(workerID int, lease Lease)
}

// FailureKind phân biệt lý do MarkUnhealthyAndRotate được gọi — xem doc
// comment của MarkUnhealthyAndRotate. Chỉ dùng cho việc GHI NHẬN/quan sát
// (thêm 2026-08-19, S2 trong audit VPN); KHÔNG đổi cách bất kỳ provider nào
// chọn/rotate server nội bộ — đó là quyết định tách riêng, có thể làm sau
// khi đã có đủ số liệu ban=x/net=y thật để biết nên đổi gì.
type FailureKind int

const (
	// FailureUnknown: caller không phân loại được (hoặc gọi từ chỗ không
	// có ngữ cảnh lỗi cụ thể, vd cleanup/shutdown) — vẫn đếm là 1 thất bại
	// chung như hành vi TRƯỚC 2026-08-19, không rơi vào ban hay network.
	FailureUnknown FailureKind = iota
	// FailureBan: ElevenLabs tự flag IP hiện tại (401 detected_unusual_activity)
	// — không phải lỗi của nguồn VPN, chỉ cần đổi sang IP khác.
	FailureBan
	// FailureNetwork: tunnel chết/timeout/nav lỗi — có thể là lỗi thật của
	// nguồn VPN đó.
	FailureNetwork
)

// Lease là handle proxy đang gán cho 1 worker. Provider có thể attach
// metadata (slot ID, expire time…) ngoài URL.
type Lease struct {
	URL        string
	AcquiredAt time.Time
	// Generation tăng mỗi lần rotation toàn cục, dùng để detect "lease cũ".
	Generation int64

	// owner: provider ĐÃ CẤP lease này, do MultiVPNProvider gán khi nó bọc
	// nhiều nguồn VPN. Bắt buộc phải có vì Generation chỉ duy nhất TRONG
	// PHẠM VI 1 provider — mỗi provider tự đếm từ 1, nên gen=3 của NordVPN
	// và gen=3 của PIA là 2 tunnel hoàn toàn khác nhau. Không có trường này
	// thì Release/MarkUnhealthyAndRotate của MultiVPNProvider không thể biết
	// phải gọi provider nào để đóng đúng tunnel (xem multi_vpn_provider.go).
	owner ProxyProvider
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

func (p *SharedCurrentProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, kind FailureKind, emit func(string)) (Lease, error) {
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
