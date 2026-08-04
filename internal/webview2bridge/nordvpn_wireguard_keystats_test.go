package webview2bridge

import "testing"

func TestBestKeyLocked(t *testing.T) {
	cases := []struct {
		name  string
		stats map[string]*keyStat
		want  string
	}{
		{
			name:  "no data at all",
			stats: map[string]*keyStat{},
			want:  "",
		},
		{
			name: "not enough attempts yet, even at 100%",
			stats: map[string]*keyStat{
				"a": {attempts: 4, successes: 4},
			},
			want: "",
		},
		{
			name: "enough attempts but below the success threshold",
			stats: map[string]*keyStat{
				"a": {attempts: 10, successes: 6}, // 60%, below the 70% bar
			},
			want: "",
		},
		{
			name: "exactly meets both thresholds",
			stats: map[string]*keyStat{
				"a": {attempts: 5, successes: 4}, // 80%
			},
			want: "a",
		},
		{
			name: "picks the higher success rate, not the higher attempt count",
			stats: map[string]*keyStat{
				"a": {attempts: 100, successes: 75}, // 75%
				"b": {attempts: 10, successes: 9},   // 90%
			},
			want: "b",
		},
		{
			name: "a key below the bar never wins over one that qualifies",
			stats: map[string]*keyStat{
				"a": {attempts: 3, successes: 3}, // 100% but too few attempts
				"b": {attempts: 5, successes: 4},  // 80%, qualifies
			},
			want: "b",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &NordVPNWireGuardProvider{keyStats: c.stats}
			got := p.bestKeyLocked()
			if got != c.want {
				t.Errorf("bestKeyLocked() = %q, want %q", got, c.want)
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
