// Package appconfig lưu cấu hình người dùng bền vững giữa các lần mở app
// (file JSON trong %UserConfigDir%/ElevenFlow/app_config.json).
package appconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Speaker — một người nói trong mode hội thoại (marker #Key dùng VoiceID này).
type Speaker struct {
	Key     int    `json:"key"`     // số sau dấu # (vd 1, 2, 3)
	VoiceID string `json:"voiceId"` // ElevenLabs voice ID
	Note    string `json:"note"`    // ghi chú: giọng gì
}

// Config — tùy chọn ghi nhớ giữa các phiên. Mở rộng thêm field khi cần.
type Config struct {
	OutputDir string    `json:"outputDir"`
	Speakers  []Speaker `json:"speakers,omitempty"`
}

var mu sync.Mutex

func filePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ElevenFlow", "app_config.json"), nil
}

// Load đọc config; file chưa có → Config rỗng (không lỗi).
func Load() (Config, error) {
	mu.Lock()
	defer mu.Unlock()
	var c Config
	p, err := filePath()
	if err != nil {
		return c, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		// File hỏng → coi như rỗng, không chặn app.
		return Config{}, nil
	}
	return c, nil
}

// Save ghi đè toàn bộ config.
func Save(c Config) error {
	mu.Lock()
	defer mu.Unlock()
	p, err := filePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

// SetOutputDir cập nhật chỉ field OutputDir (giữ nguyên field khác).
func SetOutputDir(dir string) error {
	c, err := Load()
	if err != nil {
		c = Config{}
	}
	c.OutputDir = dir
	return Save(c)
}

// SetSpeakers thay toàn bộ danh sách người nói (giữ nguyên field khác).
func SetSpeakers(list []Speaker) error {
	c, err := Load()
	if err != nil {
		c = Config{}
	}
	c.Speakers = list
	return Save(c)
}
