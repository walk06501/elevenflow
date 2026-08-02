package webview2bridge

import (
	"reflect"
	"testing"
)

func TestSplitParagraphs_BlankLine(t *testing.T) {
	in := "Đoạn một.\nVẫn đoạn một.\n\nĐoạn hai.\n\n\nĐoạn ba."
	got := SplitParagraphs(in)
	want := []string{"Đoạn một.\nVẫn đoạn một.", "Đoạn hai.", "Đoạn ba."}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestSplitParagraphs_NoBlankLine_PerLine(t *testing.T) {
	in := "Dòng 1\nDòng 2\nDòng 3"
	got := SplitParagraphs(in)
	want := []string{"Dòng 1", "Dòng 2", "Dòng 3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestSplitParagraphs_CRLF_And_Trim(t *testing.T) {
	in := "  Đoạn A  \r\n\r\n  Đoạn B \r\n"
	got := SplitParagraphs(in)
	want := []string{"Đoạn A", "Đoạn B"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestSplitParagraphs_Single(t *testing.T) {
	got := SplitParagraphs("Chỉ một đoạn duy nhất.")
	if len(got) != 1 || got[0] != "Chỉ một đoạn duy nhất." {
		t.Fatalf("got %#v", got)
	}
}

func TestSplitParagraphs_Empty(t *testing.T) {
	if got := SplitParagraphs("   \n\n  "); got != nil {
		t.Fatalf("expected nil, got %#v", got)
	}
}

func TestSplitDialogue_Basic(t *testing.T) {
	in := "#1 Xin chào.\n#2 Chào bạn.\n#1 Khỏe không?"
	got := SplitDialogue(in)
	want := []DialogueSegment{
		{Speaker: 1, Text: "Xin chào."},
		{Speaker: 2, Text: "Chào bạn."},
		{Speaker: 1, Text: "Khỏe không?"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestSplitDialogue_MultiLineTurn(t *testing.T) {
	in := "#1 Câu một.\nVẫn lượt 1.\n#2 Câu hai."
	got := SplitDialogue(in)
	want := []DialogueSegment{
		{Speaker: 1, Text: "Câu một. Vẫn lượt 1."},
		{Speaker: 2, Text: "Câu hai."},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestSplitDialogue_MarkerVariants_And_Preamble(t *testing.T) {
	in := "lời dẫn bị bỏ\n#1. Có dấu chấm.\n#2) Có ngoặc.\n#3: Có hai chấm."
	got := SplitDialogue(in)
	want := []DialogueSegment{
		{Speaker: 1, Text: "Có dấu chấm."},
		{Speaker: 2, Text: "Có ngoặc."},
		{Speaker: 3, Text: "Có hai chấm."},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestSplitDialogue_None(t *testing.T) {
	if got := SplitDialogue("không có marker nào"); len(got) != 0 {
		t.Fatalf("expected empty, got %#v", got)
	}
}
