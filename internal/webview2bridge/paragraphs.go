package webview2bridge

import (
	"regexp"
	"strconv"
	"strings"
)

var blankLineSplit = regexp.MustCompile(`\n[ \t]*\n+`)

// SplitParagraphs tách văn bản thành các đoạn (mỗi đoạn → 1 file audio riêng).
//
// Quy tắc (ưu tiên dòng trống):
//   - Nếu có ít nhất một dòng trống ngăn cách → tách theo cụm dòng trống; mỗi
//     đoạn có thể gồm nhiều dòng (các \n đơn bên trong được giữ nguyên).
//   - Nếu KHÔNG có dòng trống nào → mỗi dòng (\n) là một đoạn riêng.
//
// Khoảng trắng đầu/cuối mỗi đoạn được cắt; đoạn rỗng bị loại.
func SplitParagraphs(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}

	var rawParts []string
	if blankLineSplit.MatchString(text) {
		rawParts = blankLineSplit.Split(text, -1)
	} else {
		rawParts = strings.Split(text, "\n")
	}

	out := make([]string, 0, len(rawParts))
	for _, p := range rawParts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// DialogueSegment — một lượt nói: ai (Speaker, số sau dấu #) đọc Text gì.
type DialogueSegment struct {
	Speaker int
	Text    string
}

var dialogueMarker = regexp.MustCompile(`^\s*#(\d+)[\.\):]?\s*(.*)$`)

// SplitDialogue tách văn bản hội thoại theo marker #N ở đầu dòng.
//
// Định dạng:
//
//	#1 Xin chào.
//	#2 Chào bạn.
//	#1 Hôm nay thế nào?
//
// Mỗi marker #N mở một lượt mới; các dòng tiếp theo (không có marker) được nối
// vào lượt hiện tại. Văn bản trước marker đầu tiên bị bỏ qua. Lượt rỗng bị loại.
func SplitDialogue(text string) []DialogueSegment {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	var segs []DialogueSegment
	cur := -1
	for _, line := range strings.Split(text, "\n") {
		if m := dialogueMarker.FindStringSubmatch(line); m != nil {
			n, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			segs = append(segs, DialogueSegment{Speaker: n, Text: strings.TrimSpace(m[2])})
			cur = len(segs) - 1
			continue
		}
		if cur < 0 {
			continue // nội dung trước marker đầu tiên
		}
		extra := strings.TrimSpace(line)
		if extra == "" {
			continue
		}
		if segs[cur].Text == "" {
			segs[cur].Text = extra
		} else {
			segs[cur].Text += " " + extra
		}
	}

	out := segs[:0]
	for _, s := range segs {
		if strings.TrimSpace(s.Text) != "" {
			out = append(out, s)
		}
	}
	return out
}
