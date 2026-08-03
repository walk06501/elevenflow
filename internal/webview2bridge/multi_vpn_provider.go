package webview2bridge

import (
	"context"
	"fmt"
	"sync"
)

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
type MultiVPNProvider struct {
	mu        sync.Mutex
	providers []ProxyProvider
	next      int
}

func NewMultiVPNProvider(providers ...ProxyProvider) *MultiVPNProvider {
	return &MultiVPNProvider{providers: providers}
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
		lease, err := p.Acquire(ctx, workerID, emit)
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
