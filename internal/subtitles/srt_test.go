package subtitles

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// alignFromWords dựng Alignment từ danh sách (từ, thời lượng mỗi ký tự), chèn
// space giữa các từ — mô phỏng output 1 chunk ElevenLabs.
func alignFromWords(words []string, charDur float64, startTs float64) Alignment {
	var a Alignment
	ts := startTs
	for wi, w := range words {
		if wi > 0 {
			a.Characters = append(a.Characters, " ")
			a.Starts = append(a.Starts, ts)
			a.Ends = append(a.Ends, ts)
		}
		for _, r := range w {
			a.Characters = append(a.Characters, string(r))
			a.Starts = append(a.Starts, ts)
			ts += charDur
			a.Ends = append(a.Ends, ts)
		}
	}
	return a
}

func parseCues(srt string) []string {
	var cues []string
	blocks := strings.Split(strings.TrimSpace(srt), "\n\n")
	for _, b := range blocks {
		lines := strings.Split(strings.TrimSpace(b), "\n")
		if len(lines) < 3 {
			continue
		}
		cues = append(cues, strings.Join(lines[2:], "\n"))
	}
	return cues
}

// Lỗi 2: hai chunk nối nhau không được dính từ ("thu." + "Ngày" -> "thu.Ngày").
func TestMergeAlignments_BoundarySeparator(t *testing.T) {
	c1 := alignFromWords([]string{"hệ", "thống", "thực", "thụ."}, 0.1, 0)
	c2 := alignFromWords([]string{"Ngày", "nay,", "làm", "YouTube."}, 0.1, 0)

	merged := MergeAlignments([]Alignment{c1, c2}, 0.5)
	out, err := BuildSRT(merged, DefaultBuildOptions())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "thụ.Ngày") {
		t.Fatalf("boundary words merged into one token:\n%s", out)
	}
	if !strings.Contains(out, "thụ.") || !strings.Contains(out, "Ngày") {
		t.Fatalf("expected both words present separately:\n%s", out)
	}
}

// Lỗi 3: câu dài không được sinh cue chỉ chứa 1 từ lẻ (vd "xem.").
func TestBuildSRT_NoOrphanCue(t *testing.T) {
	sentence := []string{
		"Nó", "đã", "phát", "triển", "thành", "một", "hệ", "sinh", "thái",
		"kinh", "tế", "khổng", "lồ,", "nơi", "hàng", "triệu", "cá", "nhân,",
		"doanh", "nghiệp", "và", "tổ", "chức", "tham", "gia", "cạnh", "tranh",
		"để", "giành", "lấy", "sự", "chú", "ý", "của", "người", "xem.",
	}
	align := alignFromWords(sentence, 0.08, 0)
	out, err := BuildSRT(align, DefaultBuildOptions())
	if err != nil {
		t.Fatal(err)
	}
	cues := parseCues(out)
	if len(cues) < 2 {
		t.Fatalf("expected multiple cues, got %d:\n%s", len(cues), out)
	}
	for i, c := range cues {
		// Mỗi cue phải có ít nhất 2 từ (không còn cue 1 chữ như "xem.").
		flat := strings.ReplaceAll(c, "\n", " ")
		nWords := len(strings.Fields(flat))
		if nWords < 2 {
			t.Errorf("orphan cue %d has only %d word(s): %q\nfull:\n%s", i, nWords, c, out)
		}
	}
}

// Không cắt giữa từ trong SRT; mỗi dòng ≤ maxChars.
func TestBuildSRT_LineWidthAndWordBoundary(t *testing.T) {
	words := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		words = append(words, "abcdef")
	}
	opts := DefaultBuildOptions()
	align := alignFromWords(words, 0.05, 0)
	out, err := BuildSRT(align, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "-->") || line == "" {
			continue
		}
		if _, e := utf8.DecodeRuneInString(line); e == utf8.RuneError {
			continue
		}
		// Bỏ qua dòng số thứ tự cue.
		if isAllDigits(line) {
			continue
		}
		if utf8.RuneCountInString(line) > opts.MaxCharsPerLine {
			t.Errorf("line exceeds %d chars: %q", opts.MaxCharsPerLine, line)
		}
		// Mỗi token phải là "abcdef" nguyên vẹn (không bị xẻ).
		for _, tok := range strings.Fields(line) {
			if tok != "abcdef" {
				t.Errorf("word split in SRT: token %q in line %q", tok, line)
			}
		}
	}
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Timestamp không được chồng lấp giữa các cue.
func TestBuildSRT_NoOverlap(t *testing.T) {
	words := make([]string, 0, 30)
	for i := 0; i < 30; i++ {
		words = append(words, "test")
	}
	align := alignFromWords(words, 0.1, 0)
	out, err := BuildSRT(align, BuildOptions{MaxCharsPerLine: 20, MaxLinesPerCue: 1, MaxCueDuration: 1.0})
	if err != nil {
		t.Fatal(err)
	}
	var timings [][2]int
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "-->") {
			parts := strings.Split(l, "-->")
			timings = append(timings, [2]int{parseSRTMs(parts[0]), parseSRTMs(parts[1])})
		}
	}
	for i := 0; i+1 < len(timings); i++ {
		if timings[i][1] > timings[i+1][0] {
			t.Errorf("overlap: cue %d end %d > cue %d start %d", i+1, timings[i][1], i+2, timings[i+1][0])
		}
	}
}

func parseSRTMs(s string) int {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ",", ":")
	parts := strings.Split(s, ":")
	if len(parts) != 4 {
		return 0
	}
	p := func(v string) int {
		n := 0
		for _, c := range strings.TrimSpace(v) {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		return n
	}
	return p(parts[0])*3600000 + p(parts[1])*60000 + p(parts[2])*1000 + p(parts[3])
}

func TestMergeAlignments_Offset(t *testing.T) {
	a1 := Alignment{Characters: []string{"a", "b"}, Starts: []float64{0, 0.5}, Ends: []float64{0.5, 1.0}}
	a2 := Alignment{Characters: []string{"c"}, Starts: []float64{0}, Ends: []float64{0.5}}
	merged := MergeAlignments([]Alignment{a1, a2}, 0.5)
	// "a","b"," "(sep),"c" => 4 phần tử
	if len(merged.Characters) != 4 {
		t.Fatalf("chars: %d want 4 (%v)", len(merged.Characters), merged.Characters)
	}
	// c bắt đầu tại LastEnd(1.0)+gap(0.5)=1.5
	if merged.Starts[3] != 1.5 {
		t.Fatalf("start c: got %v want 1.5", merged.Starts[3])
	}
}
