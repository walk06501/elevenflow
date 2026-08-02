package subtitles

// Alignment — timing theo từng ký tự từ ElevenLabs with-timestamps API.
type Alignment struct {
	Characters []string
	Starts     []float64
	Ends       []float64
}

// Len số phần tử đồng bộ (min của 3 slice).
func (a Alignment) Len() int {
	n := len(a.Characters)
	if len(a.Starts) < n {
		n = len(a.Starts)
	}
	if len(a.Ends) < n {
		n = len(a.Ends)
	}
	return n
}

// LastEndTime giây kết thúc của ký tự cuối (0 nếu rỗng).
func (a Alignment) LastEndTime() float64 {
	n := a.Len()
	if n == 0 {
		return 0
	}
	return a.Ends[n-1]
}

// MergeAlignments dồn nhiều alignment (mỗi chunk TTS) lên một timeline.
// gapSec = khoảng lặng giữa chunk (0.5 khi ghép MP3 bằng ffmpeg, 0 khi raw).
//
// Giữa hai chunk luôn chèn một ký tự space ngăn cách: mỗi chunk là một request
// TTS độc lập, ký tự cuối chunk trước và ký tự đầu chunk sau không có khoảng
// trắng nối → nếu nối thẳng, buildWordUnits sẽ gộp "thu." + "Ngày" thành một
// "từ" sai ("thu.Ngày") và mất dấu kết câu. Space ngăn cách khắc phục điều này.
func MergeAlignments(parts []Alignment, gapSec float64) Alignment {
	var out Alignment
	offset := 0.0
	for i, p := range parts {
		n := p.Len()
		for j := 0; j < n; j++ {
			ch := p.Characters[j]
			if ch == "" || ch == "\n" {
				continue
			}
			out.Characters = append(out.Characters, ch)
			out.Starts = append(out.Starts, p.Starts[j]+offset)
			out.Ends = append(out.Ends, p.Ends[j]+offset)
		}
		if i < len(parts)-1 {
			boundary := p.LastEndTime() + offset
			out.Characters = append(out.Characters, " ")
			out.Starts = append(out.Starts, boundary)
			out.Ends = append(out.Ends, boundary)
			offset += p.LastEndTime() + gapSec
		}
	}
	return out
}
