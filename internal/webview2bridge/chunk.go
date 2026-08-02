package webview2bridge

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// ChunkTextInRange cắt text thành các đoạn có độ dài (rune) trong [minChars,
// maxChars] khi có thể, nhắm ~idealChars. Ưu tiên biên câu / xuống dòng như
// ChunkText cũ. Đoạn cuối có thể < minChars — nếu quá ngắn và đã có chunk
// trước, gộp vào chunk trước **chỉ khi** tổng độ dài vẫn ≤ maxChars (tránh vượt
// giới hạn API, vd. ElevenLabs anonymous 1000 ký tự).
//
// Tham số mặc định gợi ý khi max=800: min=600, ideal=700, max=800.
func ChunkTextInRange(text string, minChars, idealChars, maxChars int) []string {
	if minChars <= 0 {
		minChars = 600
	}
	if idealChars <= 0 {
		idealChars = 700
	}
	if maxChars <= 0 {
		maxChars = 800
	}
	if minChars > idealChars {
		idealChars = minChars
	}
	if idealChars > maxChars {
		maxChars = idealChars
	}

	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	runes := []rune(text)
	n := len(runes)
	if n <= maxChars {
		return []string{text}
	}

	var chunks []string
	start := 0
	for start < n {
		remain := n - start
		if remain <= maxChars {
			tail := strings.TrimSpace(string(runes[start:]))
			if tail == "" {
				break
			}
			tailRunes := utf8.RuneCountInString(tail)
			if tailRunes < minChars && len(chunks) > 0 {
				prev := strings.TrimSpace(chunks[len(chunks)-1])
				combined := strings.TrimSpace(prev + " " + tail)
				if utf8.RuneCountInString(combined) <= maxChars {
					chunks[len(chunks)-1] = combined
				} else {
					chunks = append(chunks, tail)
				}
			} else {
				chunks = append(chunks, tail)
			}
			break
		}

		minEnd := start + minChars
		maxEnd := start + maxChars
		if maxEnd > n {
			maxEnd = n
		}
		if minEnd > maxEnd {
			minEnd = maxEnd
		}

		// Ưu tiên ranh giới câu/từ trong [minEnd, maxEnd] để đoạn không quá ngắn.
		split := findSplit(runes, minEnd, maxEnd)
		if split <= start || split < minEnd || isMidWord(runes, split) {
			// Không có ranh giới tốt trong [minEnd, maxEnd]: tìm ranh giới từ gần
			// nhất trong [start, maxEnd] (chấp nhận đoạn ngắn hơn minChars còn hơn
			// cắt giữa chữ → tránh TTS đọc tách âm "c âu").
			split = findSplit(runes, start, maxEnd)
		}
		if split <= start || isMidWord(runes, split) {
			// findSplit rơi vào fallback (không có khoảng trắng nào): lùi từ maxEnd
			// về khoảng trắng gần nhất; nếu vẫn không có mới cắt cứng tại maxEnd.
			split = backToWordBoundary(runes, start, maxEnd)
		}

		piece := strings.TrimSpace(string(runes[start:split]))
		if piece != "" {
			chunks = append(chunks, piece)
		}
		start = split
		for start < n && unicode.IsSpace(runes[start]) {
			start++
		}
	}
	return chunks
}

// ChunkText cắt text thành các đoạn ≤ maxChars (rune), ưu tiên biên câu.
// Với maxChars trong khoảng rộng (smoke test dùng nhỏ hơn), dùng ChunkTextInRange
// với min/ideal tỉ lệ theo trần để không vượt maxChars.
func ChunkText(text string, maxChars int) []string {
	if maxChars <= 0 {
		maxChars = 600
	}
	if maxChars >= 400 && maxChars <= 1200 {
		minC := maxChars * 9 / 10
		idealC := maxChars * 97 / 100
		if minC < 1 {
			minC = 1
		}
		if idealC < minC {
			idealC = minC
		}
		if idealC > maxChars {
			idealC = maxChars
		}
		return ChunkTextInRange(text, minC, idealC, maxChars)
	}
	// Legacy: max nhỏ (smoke test -max 80)
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if len([]rune(text)) <= maxChars {
		return []string{text}
	}

	runes := []rune(text)
	var chunks []string
	start := 0
	for start < len(runes) {
		end := start + maxChars
		if end >= len(runes) {
			chunks = append(chunks, strings.TrimSpace(string(runes[start:])))
			break
		}
		split := findSplit(runes, start, end)
		if split <= start {
			split = end
		}
		piece := strings.TrimSpace(string(runes[start:split]))
		if piece != "" {
			chunks = append(chunks, piece)
		}
		start = split
		for start < len(runes) && unicode.IsSpace(runes[start]) {
			start++
		}
	}
	return chunks
}

// EnsureChunksWithinMax tách lại đoạn nào vượt max (rune). Gọi sau ChunkText để
// không gửi request vượt giới hạn API nếu logic gộp đoạn lỗi.
func EnsureChunksWithinMax(parts []string, max int) []string {
	if max <= 0 || len(parts) == 0 {
		return parts
	}
	var out []string
	for _, p := range parts {
		if utf8.RuneCountInString(p) <= max {
			out = append(out, p)
			continue
		}
		sub := ChunkText(p, max)
		out = append(out, sub...)
	}
	return out
}

// ChunkTextForTTS = ChunkText + EnsureChunksWithinMax (dùng chung Pool + quota).
func ChunkTextForTTS(text string, maxChars int) []string {
	p := ChunkText(text, maxChars)
	return EnsureChunksWithinMax(p, maxChars)
}

// findSplit tìm vị trí cắt tốt nhất trong [start, end]:
func findSplit(runes []rune, start, end int) int {
	for i := end - 1; i > start+(end-start)/2; i-- {
		if isSentenceEnd(runes[i]) && i+1 < len(runes) && unicode.IsSpace(runes[i+1]) {
			return i + 2
		}
	}
	for i := end - 1; i > start; i-- {
		if runes[i] == '\n' {
			return i + 1
		}
	}
	for i := end - 1; i > start+(end-start)/3; i-- {
		if (runes[i] == ',' || runes[i] == ';') && i+1 < len(runes) && unicode.IsSpace(runes[i+1]) {
			return i + 2
		}
	}
	for i := end - 1; i > start; i-- {
		if unicode.IsSpace(runes[i]) {
			return i + 1
		}
	}
	return end
}

// isMidWord true nếu vị trí split rơi vào giữa một từ (cả hai bên đều không phải
// khoảng trắng) → cắt ở đây sẽ xẻ đôi từ.
func isMidWord(runes []rune, split int) bool {
	if split <= 0 || split >= len(runes) {
		return false
	}
	return !unicode.IsSpace(runes[split-1]) && !unicode.IsSpace(runes[split])
}

// backToWordBoundary lùi từ end về khoảng trắng gần nhất trong [start, end].
// Trả về maxEnd (cắt cứng) chỉ khi cả đoạn không có khoảng trắng nào.
func backToWordBoundary(runes []rune, start, end int) int {
	for i := end - 1; i > start; i-- {
		if unicode.IsSpace(runes[i]) {
			return i + 1
		}
	}
	return end
}

func isSentenceEnd(r rune) bool {
	switch r {
	case '.', '!', '?', '。', '！', '？':
		return true
	}
	return false
}
