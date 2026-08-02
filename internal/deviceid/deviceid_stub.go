//go:build !windows

package deviceid

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
)

// StableFingerprint — bản không-Windows: hash hostname (chỉ dev).
func StableFingerprint() (string, error) {
	h, _ := os.Hostname()
	sum := sha256.Sum256([]byte("elevenflow-device-v1|"+h))
	return hex.EncodeToString(sum[:]), nil
}
