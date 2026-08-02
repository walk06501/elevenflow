package camoufoxbridge

import (
	"os"
	"path/filepath"
)

// FindBundledFFmpeg trả về đường dẫn tới ffmpeg.exe đặt cạnh file .exe phát hành (vd. ElevenFlow-1.0.1.exe, ZIP pack-release).
// Thứ tự thử:
//
//	<exeDir>/ffmpeg/bin/ffmpeg.exe   — bản Windows Essentials build thường có bin/
//	<exeDir>/ffmpeg/ffmpeg.exe
//	<exeDir>/ffmpeg.exe
func FindBundledFFmpeg() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(dir, "ffmpeg", "bin", "ffmpeg.exe"),
		filepath.Join(dir, "ffmpeg", "ffmpeg.exe"),
		filepath.Join(dir, "ffmpeg.exe"),
	}
	for _, p := range candidates {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		return p
	}
	return ""
}
