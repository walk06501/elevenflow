package camoufoxbridge

import "strings"

// FriendlyBridgeInfo chuyển tin nhắn kỹ thuật từ JS bridge sang câu ngắn cho người dùng.
// skip=true → không nên ghi log (bỏ qua emit).
func FriendlyBridgeInfo(raw string) (display string, skip bool) {
	s := strings.TrimSpace(raw)
	switch {
	case s == "starting":
		return "Đang thiết lập…", false
	case strings.HasPrefix(s, "EGRESS-IP="):
		return "", true
	case strings.HasPrefix(s, "EGRESS-IP-ERR="):
		return "Đang kiểm tra mạng…", false
	case strings.Contains(s, "injecting hcaptcha"):
		return "Đang tải bảo mật…", false
	case strings.Contains(s, "solving hcaptcha"):
		return "Đang xác minh an toàn…", false
	case strings.HasPrefix(s, "token len="):
		return "", true
	case strings.Contains(s, "POST tts"):
		return "Đang gửi yêu cầu tạo giọng…", false
	case strings.HasPrefix(s, "audio bytes="):
		return "Đang nhận âm thanh…", false
	case strings.HasPrefix(s, "DIAG:"):
		return "", true
	case strings.HasPrefix(s, "DIAG-ERR="):
		return "", true
	default:
		return s, false
	}
}

// FriendlyChunkSummary dòng kết quả từng dòng trong nhật ký (không lộ chi tiết kỹ thuật).
func FriendlyChunkSummary(ok bool, detail string) string {
	if ok {
		return "thành công"
	}
	d := strings.TrimSpace(detail)
	low := strings.ToLower(d)
	switch {
	case strings.Contains(low, "voice") && (strings.Contains(low, "invalid") || strings.Contains(low, "not found")):
		return "thất bại — kiểm tra Voice ID"
	case strings.Contains(low, "401") || strings.Contains(low, "unusual") || strings.Contains(low, "detected_unusual"):
		return "thất bại — kết nối bị từ chối (đã thử đổi mạng)"
	case strings.Contains(low, "spawn") || strings.Contains(low, "wv2") || strings.Contains(low, "disk"):
		return "thất bại — không mở được phiên làm việc"
	case strings.Contains(low, "rotate") || strings.Contains(low, "lease"):
		return "thất bại — không lấy được kết nối"
	default:
		d = strings.TrimSpace(d)
		for _, sep := range []string{"https://", "http://", "socks5://", "socks5h://"} {
			if i := strings.Index(d, sep); i >= 0 {
				d = strings.TrimSpace(d[:i])
			}
		}
		if d == "" {
			return "thất bại"
		}
		rs := []rune(d)
		if len(rs) > 100 {
			return "thất bại — " + string(rs[:97]) + "…"
		}
		return "thất bại — " + d
	}
}
