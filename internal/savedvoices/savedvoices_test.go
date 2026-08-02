package savedvoices

import "testing"

func TestNormalizeDedupe(t *testing.T) {
	in := []Saved{
		{VoiceID: "abc", Label: "A"},
		{VoiceID: " abc ", Label: "B"},
		{VoiceID: "", Label: "X"},
	}
	out := normalizeList(in)
	if len(out) != 1 {
		t.Fatalf("want 1 entry, got %d", len(out))
	}
	if out[0].VoiceID != "abc" || out[0].Label != "A" {
		t.Fatalf("got %+v (first occurrence wins)", out[0])
	}
}
