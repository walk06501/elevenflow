// Package tts giữ lại JobResult — return type ổn định cho frontend Wails binding.
// Toàn bộ HTTP client cũ (TLS-fingerprint vulnerable, dễ bị Cloudflare flag)
// + RunJobs orchestrator đã được thay bằng internal/webview2bridge.
package tts

// JobResult là kết quả 1 chunk audio. Frontend đọc qua wailsjs/go/models.ts.
type JobResult struct {
	ID      int    `json:"id"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Output  string `json:"output"`
}
