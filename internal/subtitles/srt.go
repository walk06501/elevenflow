package subtitles

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// BuildOptions điều khiển chia cue SubRip (chuẩn YouTube-friendly).
type BuildOptions struct {
	MaxCharsPerLine int
	MaxLinesPerCue  int
	MaxCueDuration  float64 // giây
}

// DefaultBuildOptions — 42 ký tự/dòng, 2 dòng/cue, tối đa ~4s/cue.
func DefaultBuildOptions() BuildOptions {
	return BuildOptions{
		MaxCharsPerLine: 42,
		MaxLinesPerCue:  2,
		MaxCueDuration:  4.0,
	}
}

type srtCue struct {
	start, end float64
	text       string
}

// wordUnit nhóm các ký tự liên tiếp (không khoảng trắng) thành một "từ".
// Với CJK (không dấu cách) mỗi ký tự là một wordUnit riêng.
type wordUnit struct {
	text    string
	start   float64
	end     float64
	sentEnd bool
}

// lineUnit một dòng phụ đề đã gom xong (kèm timing).
type lineUnit struct {
	text  string
	start float64
	end   float64
}

// buildWordUnits tạo danh sách wordUnit từ alignment ký tự.
// Không bao giờ cắt giữa chữ: tách theo khoảng trắng (VI, EN) hoặc ký tự CJK.
func buildWordUnits(align Alignment) []wordUnit {
	n := align.Len()
	var units []wordUnit
	var buf strings.Builder
	var wStart, wEnd float64
	inWord := false

	flushWord := func() {
		if buf.Len() == 0 {
			return
		}
		text := buf.String()
		lastR, _ := utf8.DecodeLastRuneInString(text)
		units = append(units, wordUnit{
			text:    text,
			start:   wStart,
			end:     wEnd,
			sentEnd: isSentenceEndRune(lastR),
		})
		buf.Reset()
		inWord = false
	}

	for i := 0; i < n; i++ {
		ch := align.Characters[i]
		st, en := align.Starts[i], align.Ends[i]
		if ch == "" || ch == "\r" {
			continue
		}
		r, _ := utf8.DecodeRuneInString(ch)
		if r == '\n' || r == ' ' || r == '\t' {
			flushWord()
			continue
		}
		if isCJKRune(r) {
			flushWord()
			units = append(units, wordUnit{
				text:    ch,
				start:   st,
				end:     en,
				sentEnd: isSentenceEndRune(r),
			})
			continue
		}
		if !inWord {
			wStart = st
			inWord = true
		}
		buf.WriteString(ch)
		wEnd = en
	}
	flushWord()
	return units
}

// BuildSRT sinh nội dung file .srt từ alignment ký tự.
// Không cắt giữa từ; cue tối đa 2 dòng × 42 ký tự, ~4s; ngắt theo câu, chia dòng
// cân bằng để không tạo cue chỉ vài ký tự lẻ.
func BuildSRT(align Alignment, opts BuildOptions) (string, error) {
	if opts.MaxCharsPerLine <= 0 {
		opts.MaxCharsPerLine = 42
	}
	if opts.MaxLinesPerCue <= 0 {
		opts.MaxLinesPerCue = 2
	}
	if opts.MaxCueDuration <= 0 {
		opts.MaxCueDuration = 4.0
	}

	units := buildWordUnits(align)
	if len(units) == 0 {
		return "", fmt.Errorf("không có alignment để tạo SRT")
	}

	cues := groupCuesFromWords(units, opts)
	fixOverlaps(cues)

	var b strings.Builder
	idx := 0
	for _, c := range cues {
		if strings.TrimSpace(c.text) == "" {
			continue
		}
		if idx > 0 {
			b.WriteByte('\n')
		}
		idx++
		fmt.Fprintf(&b, "%d\n", idx)
		fmt.Fprintf(&b, "%s --> %s\n", formatSRTTime(c.start), formatSRTTime(c.end))
		b.WriteString(c.text)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// groupCuesFromWords: tách câu (theo dấu kết câu) → pack mỗi câu thành cue cân bằng.
func groupCuesFromWords(units []wordUnit, opts BuildOptions) []srtCue {
	var sentences [][]wordUnit
	var cur []wordUnit
	for _, u := range units {
		cur = append(cur, u)
		if u.sentEnd {
			sentences = append(sentences, cur)
			cur = nil
		}
	}
	if len(cur) > 0 {
		sentences = append(sentences, cur)
	}

	var cues []srtCue
	for _, s := range sentences {
		cues = append(cues, packSentence(s, opts)...)
	}
	return cues
}

// packSentence chia một câu thành các dòng cân bằng, rồi gom dòng thành cue.
func packSentence(words []wordUnit, opts BuildOptions) []srtCue {
	if len(words) == 0 {
		return nil
	}
	maxLine := opts.MaxCharsPerLine

	// Tổng độ dài câu (gồm 1 space giữa các từ).
	total := 0
	for i, w := range words {
		if i > 0 {
			total++
		}
		total += utf8.RuneCountInString(w.text)
	}

	// Số dòng tối thiểu để vừa maxLine, rồi tính bề rộng mục tiêu để chia đều.
	nLines := (total + maxLine - 1) / maxLine
	if nLines < 1 {
		nLines = 1
	}
	target := (total + nLines - 1) / nLines
	if target > maxLine {
		target = maxLine
	}

	// Gom từ thành dòng: ngắt khi vượt maxLine, hoặc đã đạt bề rộng mục tiêu (cân bằng).
	var lines []lineUnit
	var lw []wordUnit
	lineLen := 0
	flushLine := func() {
		if len(lw) == 0 {
			return
		}
		parts := make([]string, len(lw))
		for i, w := range lw {
			parts[i] = w.text
		}
		lines = append(lines, lineUnit{
			text:  strings.Join(parts, " "),
			start: lw[0].start,
			end:   lw[len(lw)-1].end,
		})
		lw = nil
		lineLen = 0
	}
	for _, w := range words {
		wl := utf8.RuneCountInString(w.text)
		need := wl
		if lineLen > 0 {
			need = lineLen + 1 + wl
		}
		if lineLen > 0 && (need > maxLine || lineLen >= target) {
			flushLine()
		}
		lw = append(lw, w)
		if lineLen == 0 {
			lineLen = wl
		} else {
			lineLen += 1 + wl
		}
	}
	flushLine()

	// Gom dòng thành cue: tối đa MaxLinesPerCue dòng, không vượt MaxCueDuration.
	var cues []srtCue
	var cl []lineUnit
	flushCue := func() {
		if len(cl) == 0 {
			return
		}
		parts := make([]string, len(cl))
		for i, l := range cl {
			parts[i] = l.text
		}
		end := cl[len(cl)-1].end
		if end <= cl[0].start {
			end = cl[0].start + 0.05
		}
		cues = append(cues, srtCue{
			start: cl[0].start,
			end:   end,
			text:  strings.Join(parts, "\n"),
		})
		cl = nil
	}
	for _, l := range lines {
		if len(cl) > 0 {
			dur := l.end - cl[0].start
			if len(cl) >= opts.MaxLinesPerCue || dur > opts.MaxCueDuration {
				flushCue()
			}
		}
		cl = append(cl, l)
	}
	flushCue()
	return cues
}

// fixOverlaps đảm bảo cue[i].end ≤ cue[i+1].start (tránh timestamp chồng lấp).
func fixOverlaps(cues []srtCue) {
	for i := 0; i+1 < len(cues); i++ {
		if cues[i].end > cues[i+1].start {
			cues[i].end = cues[i+1].start
		}
		if cues[i].end < cues[i].start {
			cues[i].end = cues[i].start + 0.05
		}
	}
}

func isSentenceEndRune(r rune) bool {
	switch r {
	case '.', '!', '?', '…', '。', '！', '？', '；', ';':
		return true
	}
	return false
}

func isCJKRune(r rune) bool {
	return unicode.Is(unicode.Han, r) ||
		unicode.Is(unicode.Hiragana, r) ||
		unicode.Is(unicode.Katakana, r) ||
		unicode.Is(unicode.Hangul, r)
}

func formatSRTTime(sec float64) string {
	if sec < 0 {
		sec = 0
	}
	ms := int(sec*1000 + 0.5)
	h := ms / 3600000
	ms %= 3600000
	m := ms / 60000
	ms %= 60000
	s := ms / 1000
	ms %= 1000
	return fmt.Sprintf("%02d:%02d:%02d,%03d", h, m, s, ms)
}
