package webview2bridge

import "encoding/json"

// jsonUnmarshal wrapper gọn (worker.go không phải import encoding/json).
//
// Lưu ý về GC + WV2 callback (Go 1.21+ runtime.Pinner trong worker.pinner):
// theo comment trong wailsapp/go-webview2 v1.0.22 chromium.go,
// "Pinner seems to panic in some cases as reported on Discord, maybe during
// shutdown when GC detects pinned objects to be released that have not been
// unpinned." → worker.pinChromium / unpinChromium wrap defer recover().
func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
