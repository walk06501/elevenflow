package webview2bridge

import (
	"reflect"
	"testing"
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
			name: "ranks by success rate, not attempt count, highest first",
			stats: map[string]*keyStat{
				"a": {attempts: 100, successes: 75}, // 75%
				"b": {attempts: 10, successes: 9},   // 90%
			},
			want: []string{"b", "a"},
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
