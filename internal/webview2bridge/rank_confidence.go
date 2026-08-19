package webview2bridge

import "math"

// wilsonLowerBound returns the lower bound of the 95% Wilson score
// confidence interval for a success ratio — used as the SORT key wherever
// this package ranks servers/keys/providers by raw successes/attempts
// (NordVPNWireGuardProvider.rankedGoodKeysLocked, serverRanker.rankedGood,
// MultiVPNProvider.qualityRankLocked). Added 2026-08-19 after an audit
// found all three sorted on the raw ratio, which lets a small lucky sample
// (5/5 = 1.00) permanently outrank a large proven one (190/200 = 0.95) —
// the raw ratio has no notion of how much evidence backs it.
//
// This only changes the SORT ORDER within an already-eligible group; the
// eligibility gates themselves (minAttempts, the >=0.70/<0.40 bucket
// thresholds) are untouched — a key/server/provider still needs the same
// minimum sample count to be considered "good" or "bad" at all. Wilson's
// lower bound naturally converges to the raw ratio as attempts grows, so
// well-established entries are barely affected; it only reorders the
// small-sample cases where raw-ratio ranking was misleading.
//
// Cost: one sqrt per candidate per sort call — microseconds even for
// NordVPN's ~224 keys, no allocation, no new state.
func wilsonLowerBound(successes, attempts int) float64 {
	if attempts <= 0 {
		return 0
	}
	n := float64(attempts)
	phat := float64(successes) / n
	const z = 1.96 // 95% confidence
	z2 := z * z
	denom := 1 + z2/n
	center := phat + z2/(2*n)
	margin := z * math.Sqrt((phat*(1-phat)+z2/(4*n))/n)
	return (center - margin) / denom
}
