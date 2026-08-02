package savedvoices

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Saved — một Voice ID người dùng đã lưu (file JSON).
type Saved struct {
	VoiceID string `json:"voiceId"`
	Label   string `json:"label"`
}

var mu sync.Mutex

func filePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ElevenFlow", "saved_voices.json"), nil
}

func readFile() ([]Saved, error) {
	p, err := filePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return []Saved{}, nil
		}
		return nil, err
	}
	var out []Saved
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("saved_voices.json: %w", err)
	}
	return normalizeList(out), nil
}

func writeFile(list []Saved) error {
	p, err := filePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

func normalizeList(in []Saved) []Saved {
	seen := make(map[string]bool)
	var out []Saved
	for _, s := range in {
		id := strings.TrimSpace(s.VoiceID)
		if id == "" {
			continue
		}
		key := strings.ToLower(id)
		if seen[key] {
			continue
		}
		seen[key] = true
		lbl := strings.TrimSpace(s.Label)
		if lbl == "" {
			lbl = shortLabel(id)
		}
		out = append(out, Saved{VoiceID: id, Label: lbl})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Label != out[j].Label {
			return strings.ToLower(out[i].Label) < strings.ToLower(out[j].Label)
		}
		return out[i].VoiceID < out[j].VoiceID
	})
	return out
}

func shortLabel(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:6] + "…" + id[len(id)-4:]
}

// Load đọc danh sách; file chưa có → rỗng.
func Load() ([]Saved, error) {
	mu.Lock()
	defer mu.Unlock()
	return readFile()
}

// Add thêm hoặc cập nhật nhãn nếu trùng Voice ID (không phân biệt hoa thường).
func Add(voiceID, label string) error {
	mu.Lock()
	defer mu.Unlock()
	id := strings.TrimSpace(voiceID)
	if id == "" {
		return fmt.Errorf("Voice ID không được để trống")
	}
	lbl := strings.TrimSpace(label)
	if lbl == "" {
		lbl = shortLabel(id)
	}
	list, err := readFile()
	if err != nil {
		return err
	}
	found := false
	for i := range list {
		if strings.EqualFold(list[i].VoiceID, id) {
			list[i].VoiceID = id
			list[i].Label = lbl
			found = true
			break
		}
	}
	if !found {
		list = append(list, Saved{VoiceID: id, Label: lbl})
	}
	list = normalizeList(list)
	return writeFile(list)
}

// Remove xóa theo Voice ID.
func Remove(voiceID string) error {
	mu.Lock()
	defer mu.Unlock()
	id := strings.TrimSpace(voiceID)
	if id == "" {
		return nil
	}
	list, err := readFile()
	if err != nil {
		return err
	}
	var out []Saved
	for _, s := range list {
		if strings.EqualFold(s.VoiceID, id) {
			continue
		}
		out = append(out, s)
	}
	return writeFile(out)
}
