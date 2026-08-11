package webview2bridge

import (
	"context"
	"log"
	"sort"
	"time"
)

// This file turns cmd/scanwgpools from a one-off manual tool into a
// continuous, in-process background job — same idea (concurrently handshake
// N hostnames of the same public key, see if the backend is a real
// multi-session "pool" instead of an ordinary 1-connection server), just run
// automatically over the life of the process instead of by hand.
//
// Findings land in discoveredPoolCapacity (checked by capacityForKeyLocked
// alongside the hand-curated nordWGPoolKeyCapacity table) — this is what
// closes the one gap nordWGPoolKeyCapacity's own doc comment calls out:
// that table only ever gets MORE conservative on its own (a known-good key
// degrading), it never discovers a NEW pool NordVPN adds later. This file is
// the "never discovers new ones automatically" half.

const (
	// nordWGDiscoveryInterval: how often to spend a short burst testing 1
	// not-yet-classified key group. Deliberately unhurried — at 1 group per
	// tick, covering all ~224 keys takes a few days, which is fine for a
	// background/opportunistic process with no deadline. Frequent enough to
	// make steady progress, infrequent enough that even a bad tick (e.g.
	// tests right as a real job starts) is a rare, brief blip rather than a
	// standing tax on the account.
	nordWGDiscoveryInterval = 20 * time.Minute

	// nordWGDiscoveryMinHosts/nordWGDiscoveryPerGroup: same defaults as
	// cmd/scanwgpools's own flags — a pool worth caring about has enough
	// hostnames to matter, and 10 concurrent handshakes is enough to tell a
	// real pool (828 hosts, 10/10 in the 2026-08-11 manual run) from an
	// ordinary dedicated server (0/10, the other 38/40 groups tested).
	nordWGDiscoveryMinHosts = 6
	nordWGDiscoveryPerGroup = 10

	// nordWGDiscoveryPromoteBar: deliberately STRICTER than cmd/scanwgpools's
	// own ">=5/10" bar (the one au569 was hand-accepted at) — not a style
	// choice, a correctness requirement. Every discovery test result also
	// feeds THIS process's own keyStats via noteKeyResult, the same stats
	// capacityForKeyLocked checks to decide whether to keep trusting a
	// promotion (>=5 attempts and >=70% success, see that function). A
	// batch promoted at exactly 5 or 6 out of 10 (50-60%) would satisfy the
	// promotion bar but immediately FAIL the 70% trust bar on the very next
	// capacityForKeyLocked call — using those same 10 attempts — silently
	// demoting itself back to the default a moment after being promoted.
	// Requiring >=7/10 here means a promotion can never immediately
	// self-invalidate this way. cmd/scanwgpools itself has no such
	// constraint (a separate one-off process, its results never touch any
	// running server's keyStats), which is why its own bar can afford to be
	// looser and why au569 (5/10) was still fine to accept there by hand.
	nordWGDiscoveryPromoteBar = 7
)

func (p *NordVPNWireGuardProvider) discoveryLoop(ctx context.Context) {
	t := time.NewTicker(nordWGDiscoveryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.runDiscoveryTick()
		}
	}
}

// runDiscoveryTick tests exactly 1 not-yet-classified key group per call,
// skipping entirely if this account currently has any real lease open —
// discovery deliberately never competes with production traffic for slots;
// it only spends capacity this account isn't using for anything else right
// now.
func (p *NordVPNWireGuardProvider) runDiscoveryTick() {
	p.mu.Lock()
	if len(p.live) != 0 {
		p.mu.Unlock()
		return // busy serving a real job — skip this tick, try again next time
	}
	key, hosts, ok := p.nextDiscoveryCandidateLocked()
	p.mu.Unlock()
	if !ok {
		return // nothing left worth testing right now (all classified, or none big enough)
	}

	n := nordWGDiscoveryPerGroup
	if n > len(hosts) {
		n = len(hosts)
	}
	candidates := hosts[:n]

	okCount := 0
	results := make(chan bool, len(candidates))
	for _, s := range candidates {
		go func(s wgServer) {
			// tryOne is the exact same handshake+real-HTTP-GET verification
			// Acquire() uses for a real lease — deliberately reused rather
			// than duplicating scanwgpools' separate tryTunnel, and safe to
			// call directly here because it never touches p.live/p.genCtr
			// itself (that registration only happens in acquireLease after
			// probeRound returns) — these are throwaway test tunnels, not
			// real leases, and are closed immediately below either way.
			t, err := p.tryOne(s)
			if err != nil {
				results <- false
				return
			}
			t.socks.Close()
			t.dev.Close()
			results <- true
		}(s)
	}
	for i := 0; i < len(candidates); i++ {
		ok := <-results
		p.noteKeyResult(key, ok) // same live stats normal traffic feeds — capacityForKeyLocked's degrade check applies to discovered keys too, not just the hand-curated ones
		if ok {
			okCount++
		}
	}

	if okCount < nordWGDiscoveryPromoteBar {
		log.Printf("[NordVPN-WG] Discovery: key %s... (%d hosts) — %d/%d concurrent, not a pool (ordinary server)", key[:12], len(hosts), okCount, len(candidates))
		return
	}

	p.mu.Lock()
	if okCount > p.discoveredPoolCapacity[key] {
		p.discoveredPoolCapacity[key] = okCount
	}
	p.mu.Unlock()
	log.Printf("[NordVPN-WG] Discovery: key %s... (%d hosts, vd %s) — %d/%d concurrent — NEW POOL FOUND, capacity promoted to %d", key[:12], len(hosts), candidates[0].hostname, okCount, len(candidates), okCount)
}

// nextDiscoveryCandidateLocked picks the next key group worth testing:
// large enough to matter (nordWGDiscoveryMinHosts) and not already
// classified one way or the other (present in either the hand-curated
// nordWGPoolKeyCapacity or the already-discovered map). Rotates through
// them largest-first via discoveryCursor so the biggest, statistically most
// promising groups (today's one real pool was the single largest group
// tested) get tried before small ones. Caller must hold p.mu.
func (p *NordVPNWireGuardProvider) nextDiscoveryCandidateLocked() (string, []wgServer, bool) {
	type group struct {
		key   string
		hosts []wgServer
	}
	var candidates []group
	for key, hosts := range p.byKey {
		if len(hosts) < nordWGDiscoveryMinHosts {
			continue
		}
		if _, known := nordWGPoolKeyCapacity[key]; known {
			continue
		}
		if _, known := p.discoveredPoolCapacity[key]; known {
			continue
		}
		candidates = append(candidates, group{key, hosts})
	}
	if len(candidates) == 0 {
		return "", nil, false
	}
	sort.Slice(candidates, func(i, j int) bool { return len(candidates[i].hosts) > len(candidates[j].hosts) })
	idx := p.discoveryCursor % len(candidates)
	p.discoveryCursor++
	return candidates[idx].key, candidates[idx].hosts, true
}
