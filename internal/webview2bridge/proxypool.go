package webview2bridge

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"elevenflow/internal/proxyserver"
)

// secondaryLeaseWait: worker id≥1 không được chờ lease vô hạn — với chỉ 1 dòng
// proxy active, worker 0 giữ lease cả batch nên worker phụ không bao giờ
// nhận slot; chờ mãi → wg không về → không ghép MP3.
const secondaryLeaseWait = 75 * time.Second

// PoolProvider lease proxy qua /api/proxy/lease — server (Supabase atomic
// row update với FOR UPDATE SKIP LOCKED) đảm bảo:
//   - 2 user khác nhau (sessionID khác) KHÔNG bao giờ nhận cùng key tại
//     cùng thời điểm
//   - Chế độ mặc định (sharedLuna=false): mỗi worker lease một dòng proxy khác.
//   - Chế độ Luna (NewPoolProviderShared): một lease / một URL cho mọi worker;
//     vendor có thể gán IP khác theo từng kết nối TTS.
//
// Heartbeat: định kỳ gửi lease_token lên server để cập nhật leased_at (tránh
// zombie cleanup ~90s khi chunk+hCaptcha kéo dài). 3 worker song song → chu
// kỳ ngắn hơn 30s; shared Luna vẫn chỉ gửi một token.
const leaseHeartbeatInterval = 18 * time.Second

type PoolProvider struct {
	client *proxyserver.Client

	mu     sync.Mutex
	leases map[int]activeLease // workerID → lease state (per-worker mode)

	// sharedLuna: một lần LeaseWithWait cho worker 0; worker khác dùng chung URL/token.
	sharedLuna   bool
	shared       *activeLease
	sharedGate   chan struct{} // đóng sau lần lease đầu (ok hoặc lỗi) để worker phụ không treo
	sharedOpen   sync.Once
	sharedLeaseMu sync.Mutex // serial hóa lease đầu (worker 0)

	hbCtx    context.Context
	hbCancel context.CancelFunc
	hbStart  sync.Once
}

type activeLease struct {
	URL        string
	Token      string
	AcquiredAt time.Time
	Generation int64
}

// NewPoolProvider tạo PoolProvider mới (mỗi worker một lease riêng).
func NewPoolProvider(client *proxyserver.Client) *PoolProvider {
	return &PoolProvider{
		client: client,
		leases: make(map[int]activeLease),
	}
}

// NewPoolProviderShared: một lease dùng chung cho mọi worker (Luna / gateway
// đổi IP theo request). Gọi server lease đúng một lần mỗi batch.
func NewPoolProviderShared(client *proxyserver.Client) *PoolProvider {
	return &PoolProvider{
		client:     client,
		leases:     make(map[int]activeLease),
		sharedLuna: true,
		sharedGate: make(chan struct{}),
	}
}

// Acquire lease 1 proxy cho worker. Block đến khi có free key (qua server
// countdown). Nếu worker đã có lease active, trả lại — Acquire idempotent.
func (p *PoolProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	if emit == nil {
		emit = func(string) {}
	}
	p.startHeartbeat()

	if p.sharedLuna {
		return p.acquireSharedLuna(ctx, workerID, emit)
	}

	p.mu.Lock()
	if cur, ok := p.leases[workerID]; ok {
		out := cur
		p.mu.Unlock()
		return Lease{URL: out.URL, AcquiredAt: out.AcquiredAt, Generation: out.Generation}, nil
	}
	p.mu.Unlock()

	leaseCtx := ctx
	var cancel context.CancelFunc
	if workerID >= 1 {
		leaseCtx, cancel = context.WithTimeout(ctx, secondaryLeaseWait)
		defer cancel()
	}
	resp, err := p.client.LeaseWithWait(leaseCtx, "", emit)
	if err != nil {
		if workerID >= 1 && errors.Is(err, context.DeadlineExceeded) {
			return Lease{}, context.DeadlineExceeded
		}
		return Lease{}, fmt.Errorf("lease proxy: %w", err)
	}
	url := bestURL(resp)
	if url == "" {
		return Lease{}, fmt.Errorf("server trả lease ok nhưng thiếu URL")
	}

	return p.storeLease(workerID, url, resp.LeaseToken, emit), nil
}

func (p *PoolProvider) acquireSharedLuna(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	p.mu.Lock()
	if cur, ok := p.leases[workerID]; ok {
		out := cur
		p.mu.Unlock()
		return Lease{URL: out.URL, AcquiredAt: out.AcquiredAt, Generation: out.Generation}, nil
	}
	p.mu.Unlock()

	if workerID > 0 {
		select {
		case <-p.sharedGate:
		case <-ctx.Done():
			return Lease{}, ctx.Err()
		}
		p.mu.Lock()
		sh := p.shared
		if sh == nil {
			p.mu.Unlock()
			return Lease{}, fmt.Errorf("lease proxy chung thất bại (worker 0)")
		}
		l := *sh
		p.leases[workerID] = l
		p.mu.Unlock()
		emit("Đã nhận kết nối.")
		return Lease{URL: l.URL, AcquiredAt: l.AcquiredAt, Generation: l.Generation}, nil
	}

	// worker 0 — chỉ một goroutine gọi LeaseWithWait
	p.sharedLeaseMu.Lock()
	defer p.sharedLeaseMu.Unlock()

	p.mu.Lock()
	if p.shared != nil {
		if cur, ok := p.leases[workerID]; ok {
			out := cur
			p.mu.Unlock()
			return Lease{URL: out.URL, AcquiredAt: out.AcquiredAt, Generation: out.Generation}, nil
		}
		l := *p.shared
		p.leases[workerID] = l
		p.mu.Unlock()
		emit("Đã nhận kết nối.")
		return Lease{URL: l.URL, AcquiredAt: l.AcquiredAt, Generation: l.Generation}, nil
	}
	p.mu.Unlock()

	resp, err := p.client.LeaseWithWait(ctx, "", emit)
	if err != nil {
		p.sharedOpen.Do(func() { close(p.sharedGate) })
		return Lease{}, fmt.Errorf("lease proxy: %w", err)
	}
	url := bestURL(resp)
	if url == "" {
		p.sharedOpen.Do(func() { close(p.sharedGate) })
		return Lease{}, fmt.Errorf("server trả lease ok nhưng thiếu URL")
	}
	token := resp.LeaseToken
	if token == "" {
		p.sharedOpen.Do(func() { close(p.sharedGate) })
		return Lease{}, fmt.Errorf("server trả lease ok nhưng thiếu lease_token")
	}

	p.mu.Lock()
	l := activeLease{
		URL:        url,
		Token:      token,
		AcquiredAt: time.Now(),
		Generation: 1,
	}
	p.shared = &l
	p.leases[workerID] = l
	p.mu.Unlock()
	p.sharedOpen.Do(func() { close(p.sharedGate) })
	emit("Đã nhận kết nối.")
	return Lease{URL: l.URL, AcquiredAt: l.AcquiredAt, Generation: l.Generation}, nil
}

// MarkUnhealthyAndRotate: release lease cũ (banned=true → key vào cooldown
// server-side) + lease key khác (excludeURL = oldLease.URL → server không
// cấp lại cùng key cho đến khi pool xoay vòng đến nó).
func (p *PoolProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, kind FailureKind, emit func(string)) (Lease, error) {
	if emit == nil {
		emit = func(string) {}
	}

	if p.sharedLuna {
		return p.rotateSharedLuna(ctx, workerID, oldLease, emit)
	}

	p.mu.Lock()
	cur, ok := p.leases[workerID]
	if ok && cur.URL == oldLease.URL {
		delete(p.leases, workerID)
	}
	p.mu.Unlock()

	if ok {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		go func(token string) {
			defer cancel()
			_ = p.client.Release(releaseCtx, token, true)
		}(cur.Token)
		emit("Đang đổi sang kết nối khác…")
	}

	resp, err := p.client.LeaseWithWait(ctx, oldLease.URL, emit)
	if err != nil {
		return Lease{}, fmt.Errorf("lease proxy mới: %w", err)
	}
	url := bestURL(resp)
	if url == "" {
		return Lease{}, fmt.Errorf("server trả lease ok nhưng thiếu URL")
	}
	return p.storeLease(workerID, url, resp.LeaseToken, emit), nil
}

func (p *PoolProvider) rotateSharedLuna(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	p.mu.Lock()
	curTok := ""
	if p.shared != nil && p.shared.URL == oldLease.URL {
		curTok = p.shared.Token
	}
	p.mu.Unlock()

	if curTok != "" {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		go func(token string) {
			defer cancel()
			_ = p.client.Release(releaseCtx, token, true)
		}(curTok)
		emit("Đang đổi sang kết nối khác…")
	}

	resp, err := p.client.LeaseWithWait(ctx, oldLease.URL, emit)
	if err != nil {
		return Lease{}, fmt.Errorf("lease proxy mới: %w", err)
	}
	url := bestURL(resp)
	if url == "" {
		return Lease{}, fmt.Errorf("server trả lease ok nhưng thiếu URL")
	}
	token := resp.LeaseToken
	if token == "" {
		return Lease{}, fmt.Errorf("server trả lease ok nhưng thiếu lease_token")
	}

	p.mu.Lock()
	l := activeLease{
		URL:        url,
		Token:      token,
		AcquiredAt: time.Now(),
		Generation: time.Now().UnixNano(),
	}
	p.shared = &l
	p.leases[workerID] = l
	p.mu.Unlock()
	emit("Đã nhận kết nối.")
	return Lease{URL: l.URL, AcquiredAt: l.AcquiredAt, Generation: l.Generation}, nil
}

// Release worker thoát (batch xong / fatal error). Báo server free key
// nhanh để user khác / worker khác lease ngay (không phải đợi 90s zombie).
func (p *PoolProvider) Release(workerID int, lease Lease) {
	p.mu.Lock()
	cur, ok := p.leases[workerID]
	delete(p.leases, workerID)
	p.mu.Unlock()
	if !ok {
		return
	}
	releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = p.client.Release(releaseCtx, cur.Token, false)
}

// Shutdown ngừng heartbeat + release tất cả lease còn giữ. Nên gọi cuối
// batch để giải phóng key sớm (không phụ thuộc zombie cleanup).
func (p *PoolProvider) Shutdown() {
	p.mu.Lock()
	tokens := make([]string, 0, 4)
	if p.sharedLuna {
		if p.shared != nil {
			tokens = append(tokens, p.shared.Token)
		}
		p.shared = nil
	} else {
		for _, l := range p.leases {
			tokens = append(tokens, l.Token)
		}
	}
	p.leases = map[int]activeLease{}
	p.mu.Unlock()

	if p.hbCancel != nil {
		p.hbCancel()
	}
	if len(tokens) == 0 {
		return
	}
	releaseCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, t := range tokens {
		_ = p.client.Release(releaseCtx, t, false)
	}
}

func (p *PoolProvider) storeLease(workerID int, url, token string, emit func(string)) Lease {
	p.mu.Lock()
	defer p.mu.Unlock()
	gen := int64(len(p.leases)) + 1
	for _, existing := range p.leases {
		if existing.Generation >= gen {
			gen = existing.Generation + 1
		}
	}
	l := activeLease{URL: url, Token: token, AcquiredAt: time.Now(), Generation: gen}
	p.leases[workerID] = l
	emit("Đã nhận kết nối.")
	return Lease{URL: l.URL, AcquiredAt: l.AcquiredAt, Generation: l.Generation}
}

func (p *PoolProvider) startHeartbeat() {
	p.hbStart.Do(func() {
		p.hbCtx, p.hbCancel = context.WithCancel(context.Background())
		go p.heartbeatLoop(p.hbCtx)
	})
}

func (p *PoolProvider) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(leaseHeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			var tokens []string
			p.mu.Lock()
			if p.sharedLuna {
				if p.shared != nil {
					tokens = []string{p.shared.Token}
				}
			} else {
				for _, l := range p.leases {
					tokens = append(tokens, l.Token)
				}
			}
			p.mu.Unlock()
			if len(tokens) == 0 {
				continue
			}
			hbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, _ = p.client.Heartbeat(hbCtx, tokens)
			cancel()
		}
	}
}

func bestURL(r proxyserver.LeaseResponse) string {
	if r.ProxyHTTP != "" {
		return r.ProxyHTTP
	}
	return r.ProxySOCKS5
}
