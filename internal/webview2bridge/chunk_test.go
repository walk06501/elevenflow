package webview2bridge

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestChunkTextNoPieceExceedsMax(t *testing.T) {
	const max = 600
	var b strings.Builder
	for b.Len() < 50_000 {
		b.WriteString(strings.Repeat("x", 19))
		b.WriteString(". ")
	}
	chunks := ChunkTextForTTS(b.String(), max)
	for i, c := range chunks {
		n := utf8.RuneCountInString(c)
		if n > max {
			t.Fatalf("chunk %d: rune len %d > max %d (prefix %q)", i, n, max, trimForErr(c))
		}
	}
}

func TestChunkTextTailMergeStaysUnderMax(t *testing.T) {
	// Gộp đoạn cuối ngắn vào trước không được làm vượt max (lỗi cũ → ElevenLabs 1000).
	const max = 100
	minC := max * 9 / 10
	_ = minC // 90 — đoạn cuối < 90 sẽ từng bị gộp mù
	first := strings.Repeat("a", 95)  // gần max
	tail := strings.Repeat("b", 30)   // < minC, trước đây gộp → 125 > 100
	text := first + " " + tail
	chunks := ChunkTextForTTS(text, max)
	for i, c := range chunks {
		n := utf8.RuneCountInString(c)
		if n > max {
			t.Fatalf("chunk %d len %d > %d", i, n, max)
		}
	}
}

// collapseWS gom mọi chuỗi khoảng trắng thành 1 space + trim.
func collapseWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// TestChunkNoWordSplit: biên chunk không được cắt giữa từ (lỗi audio "c âu").
// Ghép lại các chunk bằng space phải tái tạo đúng văn bản gốc (đã chuẩn hóa WS).
func TestChunkNoWordSplit(t *testing.T) {
	text := "Ngày nay, làm YouTube không chỉ là câu chuyện sáng tạo nội dung " +
		"mà còn là bài toán kinh tế phức tạp liên quan đến vốn đầu tư, chi phí " +
		"sản xuất, lợi nhuận, quản trị rủi ro, tối ưu hóa dữ liệu, hành vi người " +
		"tiêu dùng và thuật toán phân phối. Rất nhiều người nhìn thấy bề nổi của " +
		"nghề YouTuber là sự nổi tiếng, thu nhập cao hoặc tự do tài chính, nhưng " +
		"phía sau đó là cả một hệ thống vận hành tương tự như một doanh nghiệp " +
		"truyền thông thực thụ."

	// Nhiều cấu hình kích thước để ép split ở các vị trí khác nhau.
	for _, cfg := range []struct{ minC, idealC, maxC int }{
		{40, 50, 60},
		{50, 60, 70},
		{30, 35, 45},
		{60, 70, 80},
	} {
		chunks := ChunkTextInRange(text, cfg.minC, cfg.idealC, cfg.maxC)
		rejoined := collapseWS(strings.Join(chunks, " "))
		want := collapseWS(text)
		if rejoined != want {
			t.Errorf("cfg=%v: word split detected\n got: %q\nwant: %q", cfg, rejoined, want)
		}
		for i, c := range chunks {
			if utf8.RuneCountInString(c) > cfg.maxC {
				t.Errorf("cfg=%v chunk %d exceeds max: %q", cfg, i, c)
			}
		}
	}
}

func trimForErr(s string) string {
	r := []rune(s)
	if len(r) <= 40 {
		return s
	}
	return string(r[:40]) + "…"
}
