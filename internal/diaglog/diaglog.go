// Package diaglog — ghi log tùy chọn ra file (hỗ trợ chẩn đoán khi user báo lỗi).
//
// Bật: đặt biến môi trường ELEVENFLOW_DIAG_LOG trước khi chạy exe:
//   - "1" hoặc "true" → %LocalAppData%\ElevenFlow\diag.log (Windows)
//   - đường dẫn đầy đủ tới file .log (ghi append UTF-8)
//
// Tắt: không đặt biến, hoặc "0" / "false".
package diaglog

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	mu       sync.Mutex
	once     sync.Once
	enabled  bool
	filePath string
	f        *os.File
	openErr  error
)

func initFromEnv() {
	raw := strings.TrimSpace(os.Getenv("ELEVENFLOW_DIAG_LOG"))
	if raw == "" || raw == "0" || strings.EqualFold(raw, "false") {
		return
	}
	enabled = true
	switch {
	case raw == "1" || strings.EqualFold(raw, "true"):
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			enabled = false
			return
		}
		filePath = filepath.Join(base, "ElevenFlow", "diag.log")
	default:
		filePath = filepath.Clean(raw)
		if filePath == "" || filePath == "." {
			enabled = false
		}
	}
}

func ensureFile() error {
	if !enabled {
		return nil
	}
	if f != nil || openErr != nil {
		return openErr
	}
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		openErr = err
		return openErr
	}
	var err error
	f, err = os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	openErr = err
	return openErr
}

// Enabled true khi ELEVENFLOW_DIAG_LOG bật (đường dẫn mục tiêu đã resolve).
func Enabled() bool {
	once.Do(initFromEnv)
	return enabled
}

// Path trả đường dẫn file log (rỗng nếu tắt hoặc chưa mở được).
func Path() string {
	once.Do(initFromEnv)
	if !enabled {
		return ""
	}
	return filePath
}

// RedactProxyURL bỏ userinfo (mật khẩu proxy) — chỉ giữ scheme + host[:port].
func RedactProxyURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Sprintf("(unparsed len=%d)", len(raw))
	}
	host := u.Hostname()
	if p := u.Port(); p != "" {
		host = net.JoinHostPort(host, p)
	}
	if u.Scheme != "" {
		return u.Scheme + "://" + host
	}
	return host
}

// Append ghi một dòng JSON + timestamp RFC3339Nano (thread-safe).
func Append(tag string, payload any) {
	once.Do(initFromEnv)
	if !enabled {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if err := ensureFile(); err != nil {
		return
	}
	ts := time.Now().Format(time.RFC3339Nano)
	var line string
	if payload == nil {
		line = fmt.Sprintf("%s\t%s\n", ts, tag)
	} else {
		b, err := json.Marshal(payload)
		if err != nil {
			line = fmt.Sprintf("%s\t%s\t%q\n", ts, tag, err.Error())
		} else {
			line = fmt.Sprintf("%s\t%s\t%s\n", ts, tag, string(b))
		}
	}
	_, _ = f.WriteString(line)
	_ = f.Sync()
}
