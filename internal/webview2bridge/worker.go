package webview2bridge

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wailsapp/go-webview2/pkg/edge"
	"golang.org/x/sys/windows"

	"elevenflow/internal/subtitles"
)

// Chunk là 1 đơn vị công việc TTS gán cho 1 file output.
type Chunk struct {
	ID         int    // chỉ số global trong batch (0-based)
	GroupID    int    // nhóm (đoạn / lượt nói) chunk thuộc về; 0 khi chạy 1 khối text duy nhất
	Voice      string // voice ID riêng cho chunk (mode hội thoại); rỗng → dùng Config.Voice
	Text       string // ≤ MaxChars characters
	OutputPath string // đường dẫn .mp3 sẽ ghi
}

// ChunkResult tổng kết 1 chunk sau khi worker xử lý xong (hoặc bỏ).
type ChunkResult struct {
	ID        int
	GroupID   int
	OK        bool
	Message   string
	Output    string
	Bytes     int64
	WorkerID  int
	Attempts  int
	Alignment subtitles.Alignment // chỉ có khi ExportSRT=true (audio_done_ts)
}

// EmitFn nhận event progress để UI hiển thị.
type EmitFn func(workerID int, chunkID int, phase, message string, done, total int)

// worker = 1 OS thread + 1 HWND + 1 Chromium + 1 LocalProxy. Sống trong
// suốt batch, tiêu thụ chunks từ shared chan.
type worker struct {
	id          int
	pool        *Pool
	chunks      <-chan Chunk
	results     chan<- ChunkResult
	dataPathDir string
	visible     bool

	// State per goroutine (chỉ truy cập từ worker goroutine):
	hwnd          windows.Handle
	chromium      *edge.Chromium
	localProxy    *LocalProxy
	currentLease  Lease
	activeDataDir string // dataDir của Chromium đang sống — dùng để cleanup khi teardown
	pinner        runtime.Pinner

	// Bridge state — set bởi Chromium callbacks (chạy trên cùng thread vì
	// callbacks fire từ DispatchMessage).
	pendingResp atomic.Pointer[bridgeMsg]
	pendingInfo atomic.Pointer[string]
	navDone     atomic.Bool
	processFail atomic.Bool
}

func newWorker(id int, pool *Pool, chunks <-chan Chunk, results chan<- ChunkResult, dataDir string, visible bool) *worker {
	return &worker{
		id:          id,
		pool:        pool,
		chunks:      chunks,
		results:     results,
		dataPathDir: dataDir,
		visible:     visible,
	}
}

// run là entry point của goroutine worker. PHẢI chạy trên goroutine đã
// LockOSThread (Pool.Run() làm điều đó).
//
// Lifecycle:
//  1. Acquire proxy + spawn WV2. Nếu fail → exit ngay, KHÔNG drain chunks
//     (để worker khác xử lý; Pool.Run sẽ drain nốt chunks còn lại sau khi
//     mọi worker exit).
//  2. Loop: lấy chunk từ chan → process → emit result → GC.
//  3. Nếu spawn lại fail giữa chừng (vd disk full) → emit FAIL cho chunk
//     hiện tại rồi exit, để worker khác chia phần còn lại.
func (w *worker) run(ctx context.Context) {
	defer func() {
		w.teardownWebView2()
		// Giải phóng slot proxy ngay khi worker thoát — nếu không, worker khác
		// đang MarkUnhealthyAndRotate/LeaseWithWait có thể deadlock vì lease vẫn
		// giữ trên DB tới tận Shutdown() (wg chỉ về khi mọi worker return).
		if w.pool != nil && w.pool.proxyProvider != nil {
			w.pool.proxyProvider.Release(w.id, Lease{})
		}
	}()

	if err := w.acquireProxyAndSpawn(ctx); err != nil {
		// Chỉ 1 slot proxy: worker phụ hết thời gian chờ lease — bình thường, không báo lỗi đỏ.
		if w.id >= 1 && errors.Is(err, context.DeadlineExceeded) {
			w.pool.emit(w.id, -1, "rotate",
				"Chỉ đủ một kết nối đồng thời — luồng phụ dừng, batch chạy một luồng.",
				-1, w.pool.totalChunks)
			return
		}
		w.pool.emit(w.id, -1, "error",
			"Không khởi động được — các dòng còn lại vẫn được xử lý.",
			-1, w.pool.totalChunks)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case chunk, ok := <-w.chunks:
			if !ok {
				return // chan closed = batch done
			}
			res := w.processChunkWithRetry(ctx, chunk)
			select {
			case w.results <- res:
			case <-ctx.Done():
				return
			}
			runtime.GC() // free base64 audio + decode buffer giữa chunks

			// Worker chết (spawn fail không retry được) → exit, để chunks còn
			// lại trong chan cho worker khác. KHÔNG ngấu nghiến rồi fail tất.
			if w.chromium == nil {
				w.pool.emit(w.id, -1, "error",
					"Dừng do không mở lại được cửa sổ — các dòng còn lại vẫn được xử lý.",
					-1, w.pool.totalChunks)
				return
			}
		}
	}
}

// processChunkWithRetry xử lý 1 chunk. 2 nhóm lỗi đều dẫn đến **rotate IP +
// respawn WV2 + retry**, mục đích "tỷ lệ tạo đủ chunk" cao nhất:
//
//  1. errUnusualActivity (HTTP 401 / "detected_unusual_activity"): IP bị
//     Cloudflare flag — bắt buộc đổi IP.
//
//  2. errTransient (Failed to fetch / network-error / NetworkError / nav
//     timeout / WV2 process failed / HTTP 5xx / 429 / api.js load failed):
//     có thể do IP đang xấu (rate limit, tunnel chết, ElevenLabs free-tier
//     limit), không xác định được nguyên nhân chính xác từ client. → Đổi IP
//     ngay vì hậu quả ít hơn so với "respawn cùng IP" (giả sử IP còn tốt
//     mà thực chất xấu thì retry lãng phí, mỗi attempt mất 10-30s).
//
//  3. Lỗi business (HTTP 4xx khác 401, voice ID sai, model không hỗ trợ
//     ngôn ngữ…): không retry, fail ngay với message gốc.
//
// MaxAttempts = 20: với pool nhiều proxy slot, mỗi rotate ~5s nếu có slot
// idle, ~60s khi phải đợi cooldown. Tệ nhất 20 × 60s = 20 phút/chunk —
// chấp nhận để đảm bảo đủ chunk thay vì bỏ.
func (w *worker) processChunkWithRetry(ctx context.Context, chunk Chunk) ChunkResult {
	const maxAttempts = 20
	res := ChunkResult{
		ID:       chunk.ID,
		GroupID:  chunk.GroupID,
		Output:   chunk.OutputPath,
		WorkerID: w.id,
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		res.Attempts = attempt
		w.pool.emit(w.id, chunk.ID, "tts",
			fmt.Sprintf("Đang xử lý dòng %d (thử %d/%d)…", chunk.ID+1, attempt, maxAttempts),
			-1, w.pool.totalChunks)

		align, err := w.processChunkOnce(ctx, chunk)
		if err == nil {
			res.OK = true
			res.Message = "ok"
			res.Alignment = align
			info, statErr := os.Stat(chunk.OutputPath)
			if statErr == nil {
				res.Bytes = info.Size()
			}
			return res
		}

		retriable := errors.Is(err, errUnusualActivity) || errors.Is(err, errTransient)
		if !retriable {
			// Lỗi business / config — fail ngay không retry.
			res.Message = err.Error()
			return res
		}

		if attempt == maxAttempts {
			res.Message = fmt.Sprintf(
				"thất bại sau %d lần thử; mỗi lần đã thử kết nối khác nhưng vẫn không ổn định.",
				maxAttempts)
			return res
		}

		reason := "kết nối bị chặn"
		if errors.Is(err, errTransient) {
			reason = "mạng không ổn"
		}
		if rotateErr := w.rotateAndRespawn(ctx, chunk.ID, reason); rotateErr != nil {
			res.Message = rotateErr.Error()
			return res
		}
	}
	res.Message = "exhausted retries"
	return res
}

// rotateAndRespawn: teardown WV2 → đợi IP mới (RotateWithWait, đến 60s) →
// respawn. Trả error khi rotate fail hoặc spawn fail (lúc đó worker.chromium
// = nil, run() loop sẽ exit để worker khác xử lý chunks còn lại).
func (w *worker) rotateAndRespawn(ctx context.Context, chunkID int, reason string) error {
	w.pool.emit(w.id, chunkID, "rotate",
		fmt.Sprintf("Đang đổi kết nối (%s)…", reason),
		-1, w.pool.totalChunks)
	w.teardownWebView2()
	oldLease := w.currentLease
	newLease, rotErr := w.pool.proxyProvider.MarkUnhealthyAndRotate(ctx, w.id, oldLease, func(msg string) {
		w.pool.emit(w.id, chunkID, "rotate",
			msg, -1, w.pool.totalChunks)
	})
	if rotErr != nil {
		return fmt.Errorf("rotate lỗi: %w", rotErr)
	}
	w.currentLease = newLease
	if spawnErr := w.spawnWebView2WithRetry(ctx, 3); spawnErr != nil {
		return fmt.Errorf("spawn WV2 mới: %w", spawnErr)
	}
	return nil
}

var (
	errUnusualActivity = errors.New("detected_unusual_activity")
	errTransient       = errors.New("transient_network_error")
)

// isTransientJSError: lỗi mạng tạm thời từ JS fetch hoặc Chromium net stack.
// Bao phủ:
//   - "Failed to fetch"   — fetch() throw khi TCP RST / TLS fail / DNS fail
//   - "NetworkError"      — XHR/fetch lower-level
//   - "ERR_CONNECTION_*"  — Chromium net error: RESET, REFUSED, CLOSED, ABORTED
//   - "ERR_TUNNEL_*"      — local proxy CONNECT chết giữa chừng
//   - "ERR_PROXY_*"       — upstream proxy auth/connect fail
//   - "ERR_EMPTY_RESPONSE"/"ERR_TIMED_OUT" — server không reply
//   - "load failed"       — script tag onerror (api.js của hcaptcha)
func isTransientJSError(s string) bool {
	if s == "" {
		return false
	}
	low := strings.ToLower(s)
	for _, m := range transientErrorMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// transientErrorMarkers: substring (case-insensitive) khi xuất hiện trong
// resp.Error → coi là transient → rotate IP + retry. Bao phủ:
//   - JS fetch errors: "Failed to fetch", "NetworkError"
//   - hCaptcha error codes (chuỗi từ error-callback): "network-error",
//     "rate-limited", "challenge-error", "challenge-closed", "close-error",
//     "internal-error", "invalid-data" — đều là transient, IP/session bị
//     từ chối.
//   - Chromium net stack: "ERR_CONNECTION_*", "ERR_TUNNEL_*", "ERR_PROXY_*",
//     "ERR_EMPTY_RESPONSE", "ERR_TIMED_OUT", "ERR_SOCKET_*", "ERR_NETWORK_*",
//     "net::ERR_*"
//   - Script tag onerror: "load failed" (api.js của hcaptcha)
//   - "expired" — hcaptcha token timeout, retry với IP mới có thể qua.
var transientErrorMarkers = []string{
	"failed to fetch",
	"networkerror",
	"network-error",
	"rate-limited",
	"challenge-error",
	"challenge-closed",
	"close-error",
	"internal-error",
	"invalid-data",
	"err_connection",
	"err_tunnel",
	"err_proxy",
	"err_empty_response",
	"err_timed_out",
	"err_socket",
	"err_network",
	"load failed",
	"net::err",
	"expired",
	"timeout",
}

// processChunkOnce thực thi 1 chunk: navigate → eval JS → đợi response →
// ghi file. Trả errUnusualActivity nếu bị 401, lỗi khác trả nguyên văn.
// Khi ExportSRT=true, trả kèm alignment (ký tự + timing) lấy từ audio_done_ts.
func (w *worker) processChunkOnce(ctx context.Context, chunk Chunk) (subtitles.Alignment, error) {
	if w.chromium == nil {
		return subtitles.Alignment{}, fmt.Errorf("chromium nil (chưa spawn?)")
	}

	// Reset state.
	w.pendingResp.Store(nil)
	w.pendingInfo.Store(nil)
	w.navDone.Store(false)

	// Navigate fresh mỗi chunk: tránh state hCaptcha cũ + đảm bảo cookies session.
	w.chromium.Navigate("https://elevenlabs.io/")
	if !w.waitNav(2 * time.Minute) {
		// Nav timeout = proxy / TCP / TLS chết → transient, retry path.
		return subtitles.Alignment{}, fmt.Errorf("%w: navigation timeout", errTransient)
	}

	// Eval TTS script.
	req := w.pool.requestFor(chunk)
	w.chromium.Eval(buildTTSScript(req))

	// Đợi terminal response (audio_done / audio_done_ts / error). Pump messages liên tục.
	timeout := 5 * time.Minute
	deadline := time.Now().Add(timeout)
	for {
		if ctx.Err() != nil {
			return subtitles.Alignment{}, ctx.Err()
		}
		if time.Now().After(deadline) {
			return subtitles.Alignment{}, fmt.Errorf("eval timeout")
		}
		if w.processFail.Load() {
			w.processFail.Store(false)
			// WV2 child process crash giữa chừng — coi là transient, respawn.
			return subtitles.Alignment{}, fmt.Errorf("%w: WV2 process failed", errTransient)
		}
		if info := w.pendingInfo.Swap(nil); info != nil {
			text, skip := FriendlyBridgeInfo(*info)
			if !skip {
				w.pool.emit(w.id, chunk.ID, "tts",
					text, -1, w.pool.totalChunks)
			}
		}
		if respPtr := w.pendingResp.Swap(nil); respPtr != nil {
			resp := *respPtr
			switch resp.Kind {
			case "audio_done":
				raw, decErr := base64.StdEncoding.DecodeString(resp.Data)
				if decErr != nil {
					return subtitles.Alignment{}, fmt.Errorf("base64 decode: %w", decErr)
				}
				if err := os.WriteFile(chunk.OutputPath, raw, 0o644); err != nil {
					return subtitles.Alignment{}, fmt.Errorf("ghi file: %w", err)
				}
				return subtitles.Alignment{}, nil
			case "audio_done_ts":
				raw, decErr := base64.StdEncoding.DecodeString(resp.Data)
				if decErr != nil {
					return subtitles.Alignment{}, fmt.Errorf("base64 decode: %w", decErr)
				}
				if err := os.WriteFile(chunk.OutputPath, raw, 0o644); err != nil {
					return subtitles.Alignment{}, fmt.Errorf("ghi file: %w", err)
				}
				align, alErr := AlignmentFromBridge(resp)
				if alErr != nil {
					// File audio đã ghi OK nhưng thiếu alignment → coi là transient
					// để retry (SRT cần alignment); hiếm khi xảy ra.
					return subtitles.Alignment{}, fmt.Errorf("%w: %v", errTransient, alErr)
				}
				return align, nil
			case "error":
				if IsUnusualActivity(resp) {
					return subtitles.Alignment{}, errUnusualActivity
				}
				if resp.Status > 0 {
					// HTTP 5xx + 429 = transient; 4xx khác = lỗi business.
					if resp.Status >= 500 || resp.Status == 429 {
						return subtitles.Alignment{}, fmt.Errorf("%w: HTTP %d: %s", errTransient, resp.Status, truncate(resp.Body, 200))
					}
					return subtitles.Alignment{}, fmt.Errorf("HTTP %d: %s", resp.Status, truncate(resp.Body, 300))
				}
				if isTransientJSError(resp.Error) {
					return subtitles.Alignment{}, fmt.Errorf("%w: %s", errTransient, resp.Error)
				}
				return subtitles.Alignment{}, fmt.Errorf("JS error: %s", resp.Error)
			default:
				return subtitles.Alignment{}, fmt.Errorf("unknown msg kind: %s", resp.Kind)
			}
		}
		if !pumpOnce() {
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func (w *worker) waitNav(timeout time.Duration) bool {
	return pumpUntil(func() bool { return w.navDone.Load() }, timeout)
}

// acquireProxyAndSpawn: lần đầu lấy proxy + tạo WV2 instance + LocalProxy.
func (w *worker) acquireProxyAndSpawn(ctx context.Context) error {
	lease, err := w.pool.proxyProvider.Acquire(ctx, w.id, func(msg string) {
		w.pool.emit(w.id, -1, "rotate", msg, -1, w.pool.totalChunks)
	})
	if err != nil {
		return fmt.Errorf("acquire proxy: %w", err)
	}
	w.currentLease = lease
	return w.spawnWebView2()
}

// spawnWebView2WithRetry retry spawn nhiều lần với backoff. Disk-full
// + file-lock thường tự fix sau vài giây nhờ async cleanup goroutine
// hoặc OS giải phóng handle. Sau N lần fail liên tiếp → bỏ cuộc, để
// worker exit graceful.
func (w *worker) spawnWebView2WithRetry(ctx context.Context, attempts int) error {
	var lastErr error
	for i := 1; i <= attempts; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := w.spawnWebView2(); err == nil {
			return nil
		} else {
			lastErr = err
			w.pool.emit(w.id, -1, "rotate",
				fmt.Sprintf("Đang thử mở lại cửa sổ (%d/%d)…", i, attempts),
				-1, w.pool.totalChunks)
			if i < attempts {
				time.Sleep(time.Duration(2*i) * time.Second) // 2s, 4s
			}
		}
	}
	return lastErr
}

// spawnWebView2: tạo HWND + LocalProxy + Chromium controller. Phải gọi từ
// worker goroutine đã LockOSThread.
//
// Mỗi spawn dùng dataDir UNIQUE (suffix UnixNano) vì:
//  1. wailsapp/go-webview2 v1.0.22 không expose Release/Close cho controller
//     + environment + webview → COM ref vẫn còn sau ShuttingDown(), msedgewebview2
//     child process chưa exit, file lock trong dataDir cũ chưa giải phóng.
//  2. Spawn mới dùng cùng dataDir → controller creation fail với E_ABORT
//     (0x80004004) vì user-data-dir đang bị process cũ giữ.
//  3. Dùng path mới hoàn toàn → bypass lock, không depends vào timing teardown.
//     activeDataDir được track để teardown wipe dir cũ async (fix #2),
//     KHÔNG đợi đến cuối batch — chống đầy ổ đĩa khi retry nhiều.
// minFreeDiskForWV2: Edge WebView2 profile + cache dùng cache nhỏ (--disk-cache
// 20MB) nhưng vẫn cần buffer FS + Win temp; 100MB là sàn thực tế — dưới đó
// spawn hay fail random.
const minFreeDiskForWV2 = 100 * 1024 * 1024

// pruneStaleWorkerDataDirs xóa thư mục worker_<id>_* cũ (mỗi lần retry/spawn
// tạo dir mới → tích lũy trên ổ TEMP). Gọi **trước** spawn để giải phóng GB.
func (w *worker) pruneStaleWorkerDataDirs() {
	entries, err := os.ReadDir(w.dataPathDir)
	if err != nil {
		return
	}
	prefix := fmt.Sprintf("worker_%d_", w.id)
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		full := filepath.Join(w.dataPathDir, e.Name())
		if w.activeDataDir != "" && full == w.activeDataDir {
			continue
		}
		_ = os.RemoveAll(full)
	}
}

func (w *worker) spawnWebView2() error {
	w.pruneStaleWorkerDataDirs()
	if free, err := freeDiskBytes(w.dataPathDir); err == nil && free < minFreeDiskForWV2 {
		return fmt.Errorf("ổ đĩa còn quá ít (%d MB free, cần ≥%d MB — đã xóa profile WV2 cũ của worker này; giải phóng thêm ổ TEMP hoặc chỉnh TEMP sang ổ khác)",
			free/(1024*1024), minFreeDiskForWV2/(1024*1024))
	}

	dataDir := filepath.Join(w.dataPathDir, fmt.Sprintf("worker_%d_%d", w.id, time.Now().UnixNano()))
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("mkdir data: %w", err)
	}

	lp, err := NewLocalProxy()
	if err != nil {
		return fmt.Errorf("local proxy: %w", err)
	}
	if err := lp.SetUpstream(w.currentLease.URL); err != nil {
		_ = lp.Close()
		return fmt.Errorf("set upstream: %w", err)
	}
	w.localProxy = lp

	hwnd, err := createHiddenWindow(w.visible)
	if err != nil {
		_ = lp.Close()
		w.localProxy = nil
		return fmt.Errorf("create window: %w", err)
	}
	w.hwnd = hwnd

	chromium := edge.NewChromium()
	chromium.DataPath = dataDir
	// Nếu có WebView2 Runtime đóng gói kèm app (bản "-fixed"), trỏ tới nó để
	// chạy trên máy CHƯA cài WebView2 hệ thống. Rỗng → dùng runtime đã cài.
	if bp := FindBundledWebView2(); bp != "" {
		chromium.BrowserPath = bp
	}
	chromium.AdditionalBrowserArgs = []string{
		"--disable-blink-features=AutomationControlled",
		"--disable-features=msSmartScreenProtection",
		"--proxy-server=http://" + lp.Addr(),
		// RAM control:
		"--disk-cache-size=20971520",  // cap disk cache 20 MB (default Edge ~250 MB)
		"--media-cache-size=10485760", // cap media cache 10 MB
		"--disable-features=BackForwardCache",
		"--disable-renderer-backgrounding",
		"--disable-background-timer-throttling",
	}
	chromium.SetErrorCallback(func(e error) {
		_ = e
		w.pool.emit(w.id, -1, "error",
			"Trình duyệt báo lỗi (sẽ thử lại nếu cần)",
			-1, w.pool.totalChunks)
	})

	chromium.MessageCallback = w.onMessage
	chromium.NavigationCompletedCallback = w.onNavigationCompleted
	chromium.ProcessFailedCallback = w.onProcessFailed

	w.chromium = chromium
	w.activeDataDir = dataDir

	if !chromium.Embed(uintptr(hwnd)) {
		w.teardownWebView2()
		return fmt.Errorf("Embed failed")
	}
	chromium.Resize()

	// Pin cấu trúc Chromium để Go GC không move/free các COM event handler
	// đã pass sang native (Go 1.26 cgo callback + WV2 IPC nhiều iframe →
	// crash trong parseVersion). pkg/edge có comment cảnh báo Pinner panic
	// khi shutdown nếu chưa Unpin → defer Unpin trong teardown.
	w.pinChromium()
	return nil
}

func (w *worker) onMessage(message string, sender *edge.ICoreWebView2, args *edge.ICoreWebView2WebMessageReceivedEventArgs) {
	var m bridgeMsg
	if err := decodeJSON(message, &m); err != nil {
		return
	}
	if m.Kind == "info" {
		s := m.Msg
		w.pendingInfo.Store(&s)
		return
	}
	mm := m
	w.pendingResp.Store(&mm)
}

func (w *worker) onNavigationCompleted(sender *edge.ICoreWebView2, args *edge.ICoreWebView2NavigationCompletedEventArgs) {
	w.navDone.Store(true)
}

func (w *worker) onProcessFailed(sender *edge.ICoreWebView2, args *edge.ICoreWebView2ProcessFailedEventArgs) {
	w.processFail.Store(true)
}

func (w *worker) teardownWebView2() {
	if w.chromium != nil {
		w.unpinChromium()
		w.chromium.MessageCallback = nil
		w.chromium.NavigationCompletedCallback = nil
		w.chromium.ProcessFailedCallback = nil
		w.chromium.ShuttingDown() // chỉ set flag; lib không expose Release thực sự
		w.chromium = nil
	}
	if w.hwnd != 0 {
		destroyWindow(w.hwnd)
		w.hwnd = 0
	}
	if w.localProxy != nil {
		_ = w.localProxy.Close()
		w.localProxy = nil
	}
	// Pump message queue để WM_DESTROY / WM_NCDESTROY propagate, msedgewebview2
	// host process nhận signal disconnect (dù không guarantee process đã exit).
	pumpForDuration(300 * time.Millisecond)

	// Async cleanup dataDir cũ: msedgewebview2.exe có thể còn handle vài giây.
	// Goroutine retry RemoveAll → giải phóng disk SỚM thay vì đợi cuối batch.
	if w.activeDataDir != "" {
		old := w.activeDataDir
		w.activeDataDir = ""
		go cleanupDataDirAsync(old)
	}
}

// cleanupDataDirAsync xóa user-data-dir cũ với retry. Edge child process
// thường giữ file lock 1-3s sau khi parent gọi ShuttingDown(); poll đến
// 30s là dư cho mọi trường hợp bình thường.
func cleanupDataDirAsync(dir string) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := os.RemoveAll(dir); err == nil {
			return
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// freeDiskBytes trả số byte free trên ổ chứa path. Dùng GetDiskFreeSpaceEx
// Win32 API (signature: lpDirectoryName, lpFreeBytesAvailableToCaller,
// lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes).
func freeDiskBytes(path string) (uint64, error) {
	if path == "" {
		path = "."
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return 0, err
	}
	// Cha thư mục có thể chưa tồn tại trên lần đầu — leo lên cho đến khi
	// thấy ổ đĩa root.
	for {
		if _, err := os.Stat(abs); err == nil {
			break
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			break
		}
		abs = parent
	}
	pUTF16, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return 0, err
	}
	var freeAvail, totalBytes, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(pUTF16, &freeAvail, &totalBytes, &totalFree); err != nil {
		return 0, err
	}
	return freeAvail, nil
}

// pinChromium / unpinChromium quản lý runtime.Pinner để giữ chromium struct
// cố định trong heap. Chỉ pin pointer chromium; các handler bên trong là
// con trỏ trên struct nên cũng ổn định theo. Bao try-recover trong unpin
// để chống panic khi GC đã dọn (như comment trong pkg/edge cảnh báo).
func (w *worker) pinChromium() {
	defer func() { _ = recover() }()
	w.pinner.Pin(w.chromium)
}

func (w *worker) unpinChromium() {
	defer func() { _ = recover() }()
	w.pinner.Unpin()
}

// (pinner field nằm trong worker struct, định nghĩa ở runtime_pinner.go cho
// rõ — Go 1.21+ có runtime.Pinner.)

// truncate giới hạn độ dài chuỗi (cho log/error).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// decodeJSON wraps để tránh import encoding/json vào file này (đã import ở tts.go).
func decodeJSON(s string, v *bridgeMsg) error {
	return jsonUnmarshal([]byte(s), v)
}

// _ giữ runtime import sống cho LockOSThread sử dụng nếu cần dùng trực tiếp ở đây.
var _ = runtime.Version
