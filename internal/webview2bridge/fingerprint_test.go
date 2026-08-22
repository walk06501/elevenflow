package webview2bridge

import "testing"

// TestRandomFingerprintNeverEmpty guards randomFingerprint against an empty
// or malformed pool (windowSizes/userAgents/langs) silently producing a
// zero-valued fingerprint.
func TestRandomFingerprintNeverEmpty(t *testing.T) {
	if len(windowSizes) == 0 || len(userAgents) == 0 || len(langs) == 0 {
		t.Fatalf("empty pool: windowSizes=%d userAgents=%d langs=%d", len(windowSizes), len(userAgents), len(langs))
	}
	for _, s := range windowSizes {
		if s[0] <= 0 || s[1] <= 0 {
			t.Errorf("invalid window size %v", s)
		}
	}
	for _, ua := range userAgents {
		if ua == "" {
			t.Errorf("empty userAgent entry")
		}
	}
	for i := 0; i < 2000; i++ {
		fp := randomFingerprint()
		if fp.width <= 0 || fp.height <= 0 || fp.userAgent == "" || fp.lang == "" {
			t.Fatalf("randomFingerprint() returned incomplete fingerprint: %+v", fp)
		}
	}
}
