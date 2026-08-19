package webview2bridge

import (
	"reflect"
	"testing"
	"time"
)

func TestRankedGoodKeysLocked(t *testing.T) {
	cases := []struct {
		name  string
		stats map[string]*keyStat
		want  []string
	}{
		{
			name:  "no data at all",
			stats: map[string]*keyStat{},
			want:  nil,
		},
		{
			name: "not enough attempts yet, even at 100%",
			stats: map[string]*keyStat{
				"a": {attempts: 4, successes: 4},
			},
			want: nil,
		},
		{
			name: "enough attempts but below the success threshold",
			stats: map[string]*keyStat{
				"a": {attempts: 10, successes: 6}, // 60%, below the 70% bar
			},
			want: nil,
		},
		{
			name: "exactly meets both thresholds",
			stats: map[string]*keyStat{
				"a": {attempts: 5, successes: 4}, // 80%
			},
			want: []string{"a"},
		},
		{
			// Changed 2026-08-19: ranking moved from the raw ratio to the
			// Wilson lower bound (rank_confidence.go) specifically so a
			// large well-proven sample outranks a small lucky one. "b" has
			// the higher raw rate (90% vs 75%) but only 10 attempts vs
			// "a"'s 100 — Wilson's lower bound for b (~0.60) sits below a's
			// (~0.66), so a now ranks first. Eligibility is unaffected:
			// both still clear the 5-attempt/70% gate on their raw rate.
			name: "ranks by confidence-adjusted rate, not raw rate — a large proven sample beats a small lucky one",
			stats: map[string]*keyStat{
				"a": {attempts: 100, successes: 75}, // 75% raw, but well-established
				"b": {attempts: 10, successes: 9},   // 90% raw, but a small sample
			},
			want: []string{"a", "b"},
		},
		{
			name: "a key below the bar is excluded even if another qualifies",
			stats: map[string]*keyStat{
				"a": {attempts: 3, successes: 3}, // 100% but too few attempts
				"b": {attempts: 5, successes: 4}, // 80%, qualifies
			},
			want: []string{"b"},
		},
		{
			name: "multiple qualifying keys are all returned, ranked",
			stats: map[string]*keyStat{
				"low":  {attempts: 10, successes: 7},  // 70%, right at the bar
				"mid":  {attempts: 10, successes: 8},  // 80%
				"high": {attempts: 10, successes: 10}, // 100%
			},
			want: []string{"high", "mid", "low"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &NordVPNWireGuardProvider{keyStats: c.stats}
			got := p.rankedGoodKeysLocked()
			if len(got) == 0 && len(c.want) == 0 {
				return // both empty: nil vs []string{} is not a meaningful difference here
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("rankedGoodKeysLocked() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestNoteKeyResult(t *testing.T) {
	p := &NordVPNWireGuardProvider{keyStats: map[string]*keyStat{}}

	p.noteKeyResult("k1", true)
	p.noteKeyResult("k1", true)
	p.noteKeyResult("k1", false)

	st := p.keyStats["k1"]
	if st == nil {
		t.Fatal("expected keyStats[\"k1\"] to exist")
	}
	if st.attempts != 3 {
		t.Errorf("attempts = %d, want 3", st.attempts)
	}
	if st.successes != 2 {
		t.Errorf("successes = %d, want 2", st.successes)
	}
}

// TestCapacityForKeyLocked locks in the "trust but verify" behavior a
// hardcoded scanwgpools-proven capacity needs: an ordinary (unlisted) key
// always gets the safe default, but a listed pool key only keeps its
// proven higher number as long as THIS process's own live traffic still
// agrees — enough real attempts at a bad success rate demotes it back to
// the default automatically, without any manual re-scan.
func TestCapacityForKeyLocked(t *testing.T) {
	const poolKey = "pool-key-hex"
	const ordinaryKey = "ordinary-key-hex"
	const proven = 10

	orig := nordWGPoolKeyCapacity
	nordWGPoolKeyCapacity = map[string]int{poolKey: proven}
	t.Cleanup(func() { nordWGPoolKeyCapacity = orig })

	cases := []struct {
		name  string
		key   string
		stats map[string]*keyStat
		want  int
	}{
		{
			name: "unlisted key always gets the safe default, regardless of stats",
			key:  ordinaryKey,
			stats: map[string]*keyStat{
				ordinaryKey: {attempts: 100, successes: 100},
			},
			want: nordWGDefaultMaxConcurrentConns,
		},
		{
			name:  "listed pool key with no live data yet keeps the proven number",
			key:   poolKey,
			stats: map[string]*keyStat{},
			want:  proven,
		},
		{
			name: "listed pool key with too few attempts to judge keeps the proven number",
			key:  poolKey,
			stats: map[string]*keyStat{
				poolKey: {attempts: 4, successes: 0}, // below minAttempts, no verdict yet
			},
			want: proven,
		},
		{
			name: "listed pool key confirmed healthy by live traffic keeps the proven number",
			key:  poolKey,
			stats: map[string]*keyStat{
				poolKey: {attempts: 20, successes: 18}, // 90%
			},
			want: proven,
		},
		{
			name: "listed pool key that live traffic proves degraded falls back to the safe default",
			key:  poolKey,
			stats: map[string]*keyStat{
				poolKey: {attempts: 20, successes: 4}, // 20% — reality stopped matching the scan
			},
			want: nordWGDefaultMaxConcurrentConns,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &NordVPNWireGuardProvider{keyStats: c.stats}
			if got := p.capacityForKeyLocked(c.key); got != c.want {
				t.Errorf("capacityForKeyLocked(%q) = %d, want %d", c.key, got, c.want)
			}
		})
	}
}

// TestDiscoveryPromotion_DoesNotSelfInvalidate is a regression test for a
// real self-consistency bug found during review: nordvpn_wireguard_discovery.go
// feeds its own test results into the SAME keyStats capacityForKeyLocked
// checks to decide whether to keep trusting a promotion. If the promotion
// bar (nordWGDiscoveryPromoteBar) were lower than the trust bar (70%, see
// capacityForKeyLocked), a batch that just barely cleared promotion (e.g.
// 5 or 6 out of 10) would immediately fail the trust check on THOSE SAME
// stats and silently demote itself back to the default a moment after
// being promoted. This locks in that the two bars are compatible: a
// discovered key, right after being promoted with a result exactly at
// nordWGDiscoveryPromoteBar, must still read back its promoted capacity.
func TestDiscoveryPromotion_DoesNotSelfInvalidate(t *testing.T) {
	const key = "freshly-discovered-key"

	p := &NordVPNWireGuardProvider{
		discoveredPoolCapacity: map[string]int{key: nordWGDiscoveryPromoteBar},
		keyStats: map[string]*keyStat{
			// Exactly what a discovery batch scoring right at the promotion
			// bar would have just recorded via noteKeyResult.
			key: {attempts: nordWGDiscoveryPerGroup, successes: nordWGDiscoveryPromoteBar},
		},
	}

	got := p.capacityForKeyLocked(key)
	if got != nordWGDiscoveryPromoteBar {
		t.Fatalf(
			"capacityForKeyLocked(%q) = %d right after being promoted at exactly the promotion bar — want %d (the promotion self-invalidated)",
			key, got, nordWGDiscoveryPromoteBar,
		)
	}
}

// TestTryAcquireSlotLocked verifies the per-key slot gate actually enforces
// its capacity (no more than N concurrent grabs succeed) and that releasing
// a slot (draining the channel, as closeLease does) frees it back up for a
// later grab — the two behaviors the whole nordWGPoolKeyCapacity feature
// depends on.
func TestTryAcquireSlotLocked(t *testing.T) {
	orig := nordWGPoolKeyCapacity
	nordWGPoolKeyCapacity = map[string]int{"pool": 3}
	t.Cleanup(func() { nordWGPoolKeyCapacity = orig })

	p := &NordVPNWireGuardProvider{
		keyStats:   map[string]*keyStat{},
		slotsByKey: map[string]chan struct{}{},
	}

	var held []chan struct{}
	for i := 0; i < 3; i++ {
		ch, ok := p.tryAcquireSlotLocked("pool")
		if !ok {
			t.Fatalf("grab #%d: expected success within proven capacity 3", i+1)
		}
		held = append(held, ch)
	}

	if _, ok := p.tryAcquireSlotLocked("pool"); ok {
		t.Fatal("4th grab should fail: capacity 3 already fully held")
	}

	// Release one, exactly like closeLease does.
	<-held[0]

	if _, ok := p.tryAcquireSlotLocked("pool"); !ok {
		t.Fatal("grab after a release should succeed: capacity freed up")
	}

	// An ordinary (unlisted) key is independent capacity — must not be
	// blocked by "pool" being fully held.
	if _, ok := p.tryAcquireSlotLocked("ordinary"); !ok {
		t.Fatal("an unrelated key's slot must not be affected by another key being full")
	}
}

// TestNextCandidate_SkipsKeysAtCapacity is a regression test for a real bug
// found during review: nextCandidate only advances past a ranked-good key
// once every one of its hostnames is in failedUntil cooldown — but a key
// being SLOT-SATURATED (all its capacity already held by real leases) never
// puts any hostname into failedUntil (that only happens on a genuine
// handshake failure). Without skipKeys, probeRound's picking loop would
// keep receiving hostnames from the very same saturated top-ranked key on
// every call (nextCandidate has plenty of non-cooldown hostnames to rotate
// through via keyHostIdx) and burn through up to len(p.servers) wasted
// iterations before giving up — never reaching a second, less-good key (or
// plain round-robin) that might have real room right now.
func TestNextCandidate_SkipsKeysAtCapacity(t *testing.T) {
	good1Hosts := []wgServer{
		{hostname: "good1-a", station: "1.1.1.1", pubHex: "good1"},
		{hostname: "good1-b", station: "1.1.1.2", pubHex: "good1"},
	}
	good2Hosts := []wgServer{
		{hostname: "good2-a", station: "2.2.2.1", pubHex: "good2"},
	}
	var allServers []wgServer
	allServers = append(allServers, good1Hosts...)
	allServers = append(allServers, good2Hosts...)

	p := &NordVPNWireGuardProvider{
		servers: allServers,
		byKey: map[string][]wgServer{
			"good1": good1Hosts,
			"good2": good2Hosts,
		},
		keyStats: map[string]*keyStat{
			// good1 ranks first (100% > 90%) — the one probeRound would
			// have skip-marked after confirming it's out of capacity.
			"good1": {attempts: 10, successes: 10},
			"good2": {attempts: 10, successes: 9},
		},
		keyHostIdx:  map[string]int{},
		failedUntil: map[string]time.Time{},
	}

	// Baseline: with nothing skipped, the top-ranked key (good1) is offered.
	s, err := p.nextCandidate(map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.pubHex != "good1" {
		t.Fatalf("baseline: got key %q, want the top-ranked key good1", s.pubHex)
	}

	// good1 marked as just-confirmed-full (what probeRound does after a
	// failed tryAcquireSlotLocked) — must now skip straight to good2,
	// not cycle through good1's other hostname first.
	s, err = p.nextCandidate(map[string]bool{"good1": true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.pubHex != "good2" {
		t.Fatalf("got key %q, want good2 (good1 should have been skipped entirely)", s.pubHex)
	}

	// Both good keys skipped — must fall through to the plain round-robin
	// over p.servers rather than erroring out (matches the "try a possibly-
	// broken server rather than refuse service" fallback philosophy).
	s, err = p.nextCandidate(map[string]bool{"good1": true, "good2": true})
	if err != nil {
		t.Fatalf("unexpected error falling back to round-robin: %v", err)
	}
	found := false
	for _, want := range allServers {
		if s.hostname == want.hostname {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("round-robin fallback returned unrecognized server %+v", s)
	}
}
