package webview2bridge

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// This file persists 2 DIFFERENT per-hostname penalty mechanisms so a
// restart doesn't forget either — both keyed by hostname (the WireGuard
// exit-server ElevenLabs actually saw traffic from), both separate from
// failedUntil (raw WG handshake miss, flat 10min, intentionally NOT
// persisted — see nordWGFailCooldown's own doc comment on why a stale
// handshake miss shouldn't outlive a restart):
//
//  1. bannedHosts (flat nordWGUnusualActivityBanCooldown, 24h): set once
//     when ElevenLabs itself flags the lease's traffic 401
//     "detected_unusual_activity" — a real signal, not a guess.
//  2. networkPenalty (escalating ladder, see nordWGNetworkBackoffLadder):
//     set/escalated on "mạng không ổn" (errTransient) rotations, reset
//     to the bottom of the ladder the next time that hostname's lease
//     completes a chunk cleanly (see NordVPNWireGuardProvider.NoteChunkOK).

// nordWGPenaltiesPath mirrors nordWGDiscoveryPath's naming/hashing scheme
// (per-account file, named from a hash of the private key so the account
// itself is never exposed via a filename).
func nordWGPenaltiesPath(privHex string) string {
	sum := sha256.Sum256([]byte(privHex))
	return filepath.Join(".", fmt.Sprintf("nordvpn_wireguard_penalties_%x.json", sum[:6]))
}

type nordWGBanEntry struct {
	Host  string    `json:"host"`
	Until time.Time `json:"until"`
}

type nordWGNetPenaltyEntry struct {
	Host  string    `json:"host"`
	Until time.Time `json:"until"`
	Level int       `json:"level"`
}

type nordWGPenaltiesFile struct {
	Bans             []nordWGBanEntry        `json:"bans"`
	NetworkPenalties []nordWGNetPenaltyEntry `json:"network_penalties"`
}

// loadNordWGPenalties reads both maps together. A missing file (first run)
// is not an error — returns 2 nil maps so the caller starts empty exactly
// like before this persistence existed. Caller is responsible for dropping
// already-expired entries (loading here on purpose keeps everything on
// disk, even past-expiry, so a rarely-restarted process's file doesn't
// silently diverge from what was actually written).
func loadNordWGPenalties(privHex string) (bans map[string]time.Time, netPen map[string]*netBackoffState, err error) {
	path := nordWGPenaltiesPath(privHex)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var saved nordWGPenaltiesFile
	if jsonErr := json.Unmarshal(data, &saved); jsonErr != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, jsonErr)
	}
	bans = make(map[string]time.Time, len(saved.Bans))
	for _, b := range saved.Bans {
		if b.Host == "" {
			continue
		}
		bans[b.Host] = b.Until
	}
	netPen = make(map[string]*netBackoffState, len(saved.NetworkPenalties))
	for _, n := range saved.NetworkPenalties {
		if n.Host == "" {
			continue
		}
		netPen[n.Host] = &netBackoffState{until: n.Until, level: n.Level}
	}
	return bans, netPen, nil
}

// saveNordWGPenalties overwrites the persisted file with the full current
// state of both maps. Called after every change (a new ban, a new
// escalation, or a reset) — infrequent enough (these are all rare-error
// paths, not per-chunk hot paths) that writing the whole file each time is
// simpler and safer than a diff/append scheme, same tradeoff already made
// by saveNordWGDiscovered.
func saveNordWGPenalties(privHex string, bans map[string]time.Time, netPen map[string]*netBackoffState) error {
	saved := nordWGPenaltiesFile{
		Bans:             make([]nordWGBanEntry, 0, len(bans)),
		NetworkPenalties: make([]nordWGNetPenaltyEntry, 0, len(netPen)),
	}
	for host, until := range bans {
		saved.Bans = append(saved.Bans, nordWGBanEntry{Host: host, Until: until})
	}
	for host, np := range netPen {
		saved.NetworkPenalties = append(saved.NetworkPenalties, nordWGNetPenaltyEntry{Host: host, Until: np.until, Level: np.level})
	}
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(nordWGPenaltiesPath(privHex), data, 0o600)
}
