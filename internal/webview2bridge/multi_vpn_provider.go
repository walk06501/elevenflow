package webview2bridge

import (
	"context"
	"sync"
)

// MultiVPNProvider round-robins across several VPN-backed ProxyProviders
// (NordVPN, PIA, ...) so every configured source contributes leases
// instead of only the first one ever being used. Each call just delegates
// to the next provider in line — the providers themselves already handle
// their own round-robin over hostnames.
type MultiVPNProvider struct {
	mu        sync.Mutex
	providers []ProxyProvider
	next      int
}

func NewMultiVPNProvider(providers ...ProxyProvider) *MultiVPNProvider {
	return &MultiVPNProvider{providers: providers}
}

func (m *MultiVPNProvider) pick() ProxyProvider {
	m.mu.Lock()
	p := m.providers[m.next%len(m.providers)]
	m.next++
	m.mu.Unlock()
	return p
}

func (m *MultiVPNProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	return m.pick().Acquire(ctx, workerID, emit)
}

func (m *MultiVPNProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	return m.pick().MarkUnhealthyAndRotate(ctx, workerID, oldLease, emit)
}

// Release is a no-op: every current member provider's own Release is
// already a no-op (see NordVPNProvider/PIAProvider), so there's nothing
// meaningful to forward even though we don't track which one issued
// which lease.
func (m *MultiVPNProvider) Release(workerID int, lease Lease) {}
