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
				"b": {attempts: 5, successes: 4},  // 80%, qualifies
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
