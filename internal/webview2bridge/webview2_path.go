package webview2bridge

import (
	"os"
	"path/filepath"
)

// FindBundledWebView2 trả về thư mục chứa fixed-version WebView2 Runtime đóng
// gói kèm app (cạnh file .exe phát hành). Dùng cho bản "-fixed" phục vụ máy
// CHƯA cài WebView2 Runtime hệ thống. Trả "" nếu không tìm thấy → app dùng
// runtime đã cài trong hệ thống như mặc định.
//
// BrowserPath (browserExecutableFolder) cần là THƯ MỤC chứa msedgewebview2.exe.
// Thứ tự thử:
//
//	<exeDir>/webview2/msedgewebview2.exe
//	<exeDir>/WebView2Runtime/msedgewebview2.exe
//	<exeDir>/webview2/<subdir>/msedgewebview2.exe   — cab fixed-version giải nén ra thư mục con theo phiên bản
func FindBundledWebView2() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)

	roots := []string{
		filepath.Join(dir, "webview2"),
		filepath.Join(dir, "WebView2Runtime"),
	}

	const marker = "msedgewebview2.exe"
	for _, root := range roots {
		if fileExists(filepath.Join(root, marker)) {
			return root
		}
	}
	// Thử thêm 1 cấp thư mục con (vd Microsoft.WebView2.FixedVersionRuntime.<ver>.x64/).
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			sub := filepath.Join(root, e.Name())
			if fileExists(filepath.Join(sub, marker)) {
				return sub
			}
		}
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
