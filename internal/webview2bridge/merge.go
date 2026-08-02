package webview2bridge

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// MergeOptions điều khiển bước ghép output.mp3.
type MergeOptions struct {
	// GapSec — khoảng lặng (giây) chèn **giữa** các chunk khi dùng ffmpeg (mặc định 0.5).
	// = 0 → không chèn (ghép byte thô như cũ).
	GapSec float64
	// FFmpegExe — đường dẫn ffmpeg.exe; rỗng → FindBundledFFmpeg() (cạnh exe).
	FFmpegExe string
}

// MergeChunks ghép các MP3 chunk → một file (mặc định có khoảng lặng 0.5s qua ffmpeg nếu có).
func MergeChunks(results []ChunkResult, outputPath string) (int64, error) {
	return MergeChunksWithOptions(results, outputPath, MergeOptions{GapSec: 0.5})
}

// MergeChunksWithOptions giống MergeChunks nhưng cho phép tắt gap hoặc chỉ định ffmpeg.
func MergeChunksWithOptions(results []ChunkResult, outputPath string, opts MergeOptions) (int64, error) {
	if len(results) == 0 {
		return 0, fmt.Errorf("không có chunk nào để ghép")
	}
	for _, r := range results {
		if !r.OK {
			return 0, fmt.Errorf("chunk %d chưa thành công (%s) — không ghép", r.ID+1, r.Message)
		}
		if r.Output == "" {
			return 0, fmt.Errorf("chunk %d không có đường dẫn output", r.ID+1)
		}
	}

	sorted := make([]ChunkResult, len(results))
	copy(sorted, results)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	ff := opts.FFmpegExe
	if ff == "" {
		ff = FindBundledFFmpeg()
	}
	if ff != "" && opts.GapSec > 0 {
		return mergeChunksFFmpeg(sorted, outputPath, ff, opts.GapSec)
	}
	return mergeChunksRaw(sorted, outputPath)
}

// mergeChunksFFmpeg: tạo MP3 im lặng (lavfi) + concat demuxer + encode lại lame (mượt ranh giới hơn ghép thô).
func mergeChunksFFmpeg(sorted []ChunkResult, outputPath, ffmpeg string, gapSec float64) (int64, error) {
	tmpDir, err := os.MkdirTemp("", "elevenflow-merge-*")
	if err != nil {
		return 0, fmt.Errorf("temp merge: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	silencePath := filepath.Join(tmpDir, "_gap.mp3")
	silenceCmd := exec.Command(ffmpeg,
		"-hide_banner", "-loglevel", "error", "-nostdin", "-y",
		"-f", "lavfi", "-i", "anullsrc=channel_layout=stereo:sample_rate=44100",
		"-t", fmt.Sprintf("%g", gapSec),
		"-c:a", "libmp3lame", "-q:a", "4",
		silencePath,
	)
	prepareExecHideWindow(silenceCmd)
	var silStderr bytes.Buffer
	silenceCmd.Stderr = &silStderr
	if err := silenceCmd.Run(); err != nil {
		return 0, fmt.Errorf("ffmpeg khoảng lặng %.2fs: %w — %s", gapSec, err, truncateMsg(silStderr.String(), 400))
	}

	var concatLines []string
	for i := range sorted {
		dst := filepath.Join(tmpDir, fmt.Sprintf("c_%03d.mp3", i))
		if err := writeChunkFile(dst, sorted[i].Output, i > 0); err != nil {
			return 0, fmt.Errorf("chuẩn bị chunk %d: %w", sorted[i].ID+1, err)
		}
		abs, err := filepath.Abs(dst)
		if err != nil {
			abs = dst
		}
		concatLines = append(concatLines, "file "+ffmpegConcatPathQuoted(abs))
		if i < len(sorted)-1 {
			absS, err := filepath.Abs(silencePath)
			if err != nil {
				absS = silencePath
			}
			concatLines = append(concatLines, "file "+ffmpegConcatPathQuoted(absS))
		}
	}

	listPath := filepath.Join(tmpDir, "concat.txt")
	if err := os.WriteFile(listPath, []byte(strings.Join(concatLines, "\n")+"\n"), 0o600); err != nil {
		return 0, fmt.Errorf("ghi concat.txt: %w", err)
	}

	// Đuôi phải là .mp3 — ffmpeg chọn muxer theo extension; ".ff.part" gây lỗi Invalid argument.
	tmpOut := outputPath + ".tmp.mp3"
	_ = os.Remove(tmpOut)
	concatCmd := exec.Command(ffmpeg,
		"-hide_banner", "-loglevel", "error", "-nostdin", "-y",
		"-f", "concat", "-safe", "0", "-i", listPath,
		"-c:a", "libmp3lame", "-q:a", "2",
		tmpOut,
	)
	prepareExecHideWindow(concatCmd)
	var concStderr bytes.Buffer
	concatCmd.Stderr = &concStderr
	if err := concatCmd.Run(); err != nil {
		return 0, fmt.Errorf("ffmpeg ghép concat: %w — %s", err, truncateMsg(concStderr.String(), 600))
	}
	if err := os.Remove(outputPath); err != nil && !os.IsNotExist(err) {
		return 0, fmt.Errorf("xoá output cũ: %w", err)
	}
	if err := os.Rename(tmpOut, outputPath); err != nil {
		return 0, fmt.Errorf("rename output: %w", err)
	}
	st, err := os.Stat(outputPath)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

func ffmpegConcatPathQuoted(abs string) string {
	s := filepath.ToSlash(abs)
	s = strings.ReplaceAll(s, "'", "'\\''")
	return "'" + s + "'"
}

func truncateMsg(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func mergeChunksRaw(sorted []ChunkResult, outputPath string) (int64, error) {
	tmpPath := outputPath + ".part"
	_ = os.Remove(tmpPath)
	out, err := os.Create(tmpPath)
	if err != nil {
		return 0, fmt.Errorf("tạo file tạm: %w", err)
	}
	defer func() {
		_ = out.Close()
		_ = os.Remove(tmpPath)
	}()

	var totalWritten int64
	for i, r := range sorted {
		n, err := appendChunk(out, r.Output, i > 0)
		if err != nil {
			return 0, fmt.Errorf("ghép chunk %d (%s): %w", r.ID+1, r.Output, err)
		}
		totalWritten += n
	}
	if err := out.Sync(); err != nil {
		return 0, fmt.Errorf("flush file ghép: %w", err)
	}
	if err := out.Close(); err != nil {
		return 0, fmt.Errorf("close file tạm: %w", err)
	}
	_ = os.Remove(outputPath)
	if err := os.Rename(tmpPath, outputPath); err != nil {
		return 0, fmt.Errorf("rename %s → %s: %w", tmpPath, outputPath, err)
	}
	return totalWritten, nil
}

func writeChunkFile(dstPath, srcPath string, stripID3 bool) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer func() { _ = dst.Close() }()
	if stripID3 {
		if err := skipID3v2(src); err != nil {
			return fmt.Errorf("skip ID3v2: %w", err)
		}
	}
	_, err = io.Copy(dst, src)
	return err
}

// appendChunk copy 1 chunk vào writer. Nếu stripID3 = true → bỏ ID3v2 header
// ở đầu file trước khi copy phần còn lại.
func appendChunk(w io.Writer, path string, stripID3 bool) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	if stripID3 {
		if err := skipID3v2(f); err != nil {
			return 0, fmt.Errorf("skip ID3v2: %w", err)
		}
	}
	return io.Copy(w, f)
}

// skipID3v2 đọc 10 byte đầu, nếu là ID3v2 header thì seek qua tag (10 +
// synchsafe-size). Nếu không phải ID3 → seek về 0 (giữ nguyên). Lỗi I/O
// được trả lại.
//
// ID3v2 header layout (10 bytes):
//
//	"ID3" (3) | ver (2) | flags (1) | size (4 synchsafe = mỗi byte MSB=0,
//	  real_size = b[0]<<21 | b[1]<<14 | b[2]<<7 | b[3])
func skipID3v2(f *os.File) error {
	var hdr [10]byte
	n, err := io.ReadFull(f, hdr[:])
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		_, _ = f.Seek(0, io.SeekStart)
		return nil
	}
	if err != nil {
		return err
	}
	if n < 10 || hdr[0] != 'I' || hdr[1] != 'D' || hdr[2] != '3' {
		_, _ = f.Seek(0, io.SeekStart)
		return nil
	}
	size := int64(hdr[6]&0x7F)<<21 |
		int64(hdr[7]&0x7F)<<14 |
		int64(hdr[8]&0x7F)<<7 |
		int64(hdr[9]&0x7F)
	if _, err := f.Seek(size, io.SeekCurrent); err != nil {
		return err
	}
	return nil
}
