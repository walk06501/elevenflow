//go:build windows

package deviceid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// StableFingerprint — hash cố định theo máy (Windows MachineGuid), không gửi raw GUID.
func StableFingerprint() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("registry: %w", err)
	}
	defer k.Close()
	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", fmt.Errorf("MachineGuid: %w", err)
	}
	guid = strings.ToLower(strings.TrimSpace(guid))
	if len(guid) < 8 {
		return "", fmt.Errorf("MachineGuid rỗng")
	}
	sum := sha256.Sum256([]byte("elevenflow-device-v1|" + guid))
	return hex.EncodeToString(sum[:]), nil
}
