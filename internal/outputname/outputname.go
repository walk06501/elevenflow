package outputname

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var invalidWin = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)

// SanitizeStem chuẩn hóa tên gốc file (không có đuôi .mp3), an toàn trên Windows.
func SanitizeStem(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = invalidWin.ReplaceAllString(s, "_")
	var b strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) && r != unicode.MaxRune {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	s = strings.Trim(b.String(), " .")
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	rs := []rune(s)
	if len(rs) > 80 {
		s = string(rs[:80])
	}
	s = strings.Trim(s, "._- ")
	if s == "" {
		return ""
	}
	// Tránh tên dành riêng trên Windows
	upper := strings.ToUpper(s)
	switch upper {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3":
		return "_" + s
	}
	return s
}

// NextBatchSubdir tạo thư mục con trong parent: YYYY-MM-DD_01, _02, … (theo ngày local).
func NextBatchSubdir(parent string) (string, error) {
	if err := ensureDir(parent); err != nil {
		return "", err
	}
	day := time.Now().In(time.Local).Format("2006-01-02")
	pat := regexp.MustCompile(`^` + regexp.QuoteMeta(day) + `_(\d+)$`)
	maxN := 0
	entries, err := os.ReadDir(parent)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		m := pat.FindStringSubmatch(name)
		if len(m) != 2 {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		if n > maxN {
			maxN = n
		}
	}
	next := maxN + 1
	sub := day + "_" + formatSeq(next)
	full := filepath.Join(parent, sub)
	if err := ensureDir(full); err != nil {
		return "", err
	}
	return full, nil
}

func formatSeq(n int) string {
	if n < 100 {
		return fmt.Sprintf("%02d", n)
	}
	return strconv.Itoa(n)
}

func ensureDir(p string) error {
	return os.MkdirAll(p, 0o700)
}
