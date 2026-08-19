package webview2bridge

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	// feeds THIS process's own discoveryStats via noteDiscoveryResult, which
	// capacityForKeyLocked reads (combined with keyStats) to decide whether
	// to keep trusting a promotion (>=5 combined attempts and >=70% success,
	// see that function). A batch promoted at exactly 5 or 6 out of 10
	// (50-60%) would satisfy the promotion bar but immediately FAIL the 70%
	// trust bar on the very next capacityForKeyLocked call — using those
	// same 10 attempts — silently demoting itself back to the default a
	// moment after being promoted. Requiring >=7/10 here means a promotion
	// can never immediately self-invalidate this way. cmd/scanwgpools itself
	// has no such constraint (a separate one-off process, its results never
	// touch any running server's stats), which is why its own bar can
	// afford to be looser and why au569 (5/10) was still fine to accept
	// there by hand.
	nordWGDiscoveryPromoteBar = 7
)

// nordWGDiscoveryPath returns a stable per-account file for persisting
// discoveredPoolCapacity across restarts — named from a hash of the
// account's private key (never the key itself) so the account isn't
// exposed via a filename or directory listing. Added 2026-08-19: without
// this, every restart wiped discoveredPoolCapacity back to empty
// (deliberately, per the original doc comment's "quán tính trong 1 lần
// chạy dài là đủ" reasoning) — a fine assumption if the process ran for
// weeks uninterrupted, but this VPS gets restarted for deploys often
// enough (twice in one day, this session) that days of a 20-min-per-tick
// background scan (nordWGDiscoveryInterval, ~224 key groups total) kept
// getting thrown away before ever covering the list. Mirrors
// mullvad_wireguard_provider.go's mullvadKeysPath/loadMullvadKeys pattern,
// which fixed the same class of "restart loses accumulated state" bug for
// Mullvad's device registrations.
func nordWGDiscoveryPath(privHex string) string {
	sum := sha256.Sum256([]byte(privHex))
	return filepath.Join(".", fmt.Sprintf("nordvpn_discovered_pools_%x.json", sum[:6]))
}

// nordWGDiscoveredEntry carries a capacity claim TOGETHER WITH the evidence
// behind it (Attempts/Successes, from discoveryStats). Added 2026-08-19,
// same day as the original persistence fix: the first version of this
// struct only had Key/Capacity — persisting the claim without the evidence
// broke capacityForKeyLocked's own documented guarantee ("can only get more
// conservative, never silently keep trusting a stale number"), because a
// key demoted by live traffic between saves would reload at full capacity
// with an empty stats map on the next restart. Mirrors the lesson from
// mullvad_wireguard_provider.go's key persistence: persist a claim and the
// evidence for it together, or persist neither.
type nordWGDiscoveredEntry struct {
	Key       string `json:"key"`
	Capacity  int    `json:"capacity"`
	Attempts  int    `json:"attempts"`
	Successes int    `json:"successes"`
}

// loadNordWGDiscovered reads a previously-saved discovery cache, returning
// the capacity map (for discoveredPoolCapacity) and the evidence map (for
// discoveryStats) together — always load both or neither, never one without
// the other. A missing file (first run, or an account never scanned before)
// is not an error — returns nil, nil, nil so the caller starts from empty
// maps exactly like before this fix existed.
func loadNordWGDiscovered(privHex string) (map[string]int, map[string]*keyStat, error) {
	path := nordWGDiscoveryPath(privHex)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var saved []nordWGDiscoveredEntry
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	capacity := make(map[string]int, len(saved))
	stats := make(map[string]*keyStat, len(saved))
	for _, s := range saved {
		if s.Key == "" || s.Capacity <= 0 {
			continue
		}
		if s.Attempts <= 0 {
			// No evidence backs this claim — either a leftover file from
			// the OLD version of this fix (2026-08-19, same day: shipped
			// once with Key/Capacity only, before Attempts/Successes were
			// added a few hours later) or a hand-edited/corrupted entry.
			// Skip it entirely rather than loading a capacity with nothing
			// to degrade-check against — capacityForKeyLocked's guard only
			// fires at attempts>=5, so an Attempts=0 entry would otherwise
			// be trusted unconditionally, silently reproducing the exact
			// bug this persistence format was just changed to prevent.
			// Discovery will naturally re-test this key group later.
			continue
		}
		capacity[s.Key] = s.Capacity
		stats[s.Key] = &keyStat{attempts: s.Attempts, successes: s.Successes}
	}
	return capacity, stats, nil
}

// saveNordWGDiscovered persists the full current discovery map — capacity
// AND its backing evidence, zipped together by key — overwriting whatever
// was there before. Called after every new promotion so the next restart
// resumes with everything found so far instead of only the latest single
// result. Entries with no matching stats (should not normally happen, since
// a promotion always writes both maps under the same lock) are written with
// Attempts=0 rather than dropped, so a load-then-immediately-degrade is the
// fail-safe direction, not a load-then-trust-forever one.
func saveNordWGDiscovered(privHex string, capacity map[string]int, stats map[string]*keyStat) error {
	saved := make([]nordWGDiscoveredEntry, 0, len(capacity))
	for k, v := range capacity {
		entry := nordWGDiscoveredEntry{Key: k, Capacity: v}
		if st, ok := stats[k]; ok {
			entry.Attempts = st.attempts
			entry.Successes = st.successes
		}
		saved = append(saved, entry)
	}
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(nordWGDiscoveryPath(privHex), data, 0o600)
}

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
// skipping entirely if this account currently has any real lease open right
// now — discovery only spends capacity this account isn't using for
// anything else AT THE MOMENT IT STARTS. This is a snapshot check, not a
// lock held for the whole test: the batch below (a handful of concurrent
// handshakes, done in a few seconds via tryOne, same as a real probeRound)
// deliberately bypasses tryAcquireSlotLocked/slotsByKey entirely so it can
// test capacity an unproven key isn't yet trusted for — which also means a
// real request that starts mid-batch and happens to land on the SAME
// untested key (only reachable via nextCandidate's round-robin fallback,
// since discovery only ever targets keys with no rankedGoodKeysLocked
// standing yet) isn't blocked by it either. That overlap is rare by
// construction and self-heals the same way any other transient handshake
// hiccup does (noteFailure/rotation/MultiVPNProvider falling back to
// another source) — not prevented outright, just made unlikely and cheap
// when it happens.
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
		// noteDiscoveryResult, NOT noteKeyResult — this batch deliberately
		// tests at concurrency nordWGDiscoveryPerGroup (10) to see if the
		// key is secretly a pool, but an ORDINARY key (the common case) can
		// only sustain nordWGDefaultMaxConcurrentConns (1) by design. Ten
		// results from one tick would bank ~9 failures against an ordinary
		// key in the SAME map rankedGoodKeysLocked reads for promotion —
		// see noteKeyResult's doc comment for the full incident this caused
		// (fixed 2026-08-19): real traffic could then never promote that
		// key, needing 22+ consecutive real successes to outweigh one
		// discovery tick, which itself re-runs periodically. discoveryStats
		// is a separate map so this test's own by-design overload never
		// contaminates the statistics real single-connection traffic relies
		// on — capacityForKeyLocked still reads both (combined) for its
		// degrade check, which is the one place discovery evidence SHOULD
		// count.
		p.noteDiscoveryResult(key, ok)
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
	capSnapshot := make(map[string]int, len(p.discoveredPoolCapacity))
	for k, v := range p.discoveredPoolCapacity {
		capSnapshot[k] = v
	}
	statsSnapshot := make(map[string]*keyStat, len(p.discoveryStats))
	for k, st := range p.discoveryStats {
		cp := *st
		statsSnapshot[k] = &cp
	}
	p.mu.Unlock()
	log.Printf("[NordVPN-WG] Discovery: key %s... (%d hosts, vd %s) — %d/%d concurrent — NEW POOL FOUND, capacity promoted to %d", key[:12], len(hosts), candidates[0].hostname, okCount, len(candidates), okCount)
	if err := saveNordWGDiscovered(p.privHex, capSnapshot, statsSnapshot); err != nil {
		log.Printf("[NordVPN-WG] Warning: failed to persist discovered pool cache: %v", err)
	}
}

// nextDiscoveryCandidateLocked picks the next key group worth testing:
// large enough to matter (nordWGDiscoveryMinHosts) and not already
// CONFIRMED a pool (present in either the hand-curated nordWGPoolKeyCapacity
// or the already-discovered map). A key that tested below
// nordWGDiscoveryPromoteBar is NOT excluded here and stays eligible for a
// later re-test — there is no separate "confirmed ordinary" memory. This is
// deliberate, not a missed case: a tick only ever runs when the account
// would otherwise sit fully idle (see runDiscoveryTick), so re-testing an
// already-ordinary key costs nothing that would have gone to something more
// useful, and it's the only way this ever notices NordVPN promoting a
// previously-ordinary server into a real pool later.
//
// Rotates through eligible groups largest-first via discoveryCursor so the
// biggest, statistically most promising groups (today's one real pool was
// the single largest group tested) get tried before small ones. Caller
// must hold p.mu.
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
