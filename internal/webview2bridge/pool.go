package webview2bridge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"elevenflow/internal/diaglog"
	"elevenflow/internal/outputdir"
)

const defaultMaxChunkChars = 600

// Config bundle các tham số runtime của Pool.
type Config struct {
	NumWorkers     int     // số WV2 chạy song song; mặc định 2
	MaxChars       int     // độ dài tối đa mỗi chunk (rune), mặc định 600 — dùng ChunkText (ưu tiên biên câu)
	OutputDir      string  // thư mục ghi MP3 output (thường là thư mục con theo ngày)
	OutputFileStem string  // tên gốc file (không .mp3); rỗng → chunk_0000.mp3 / output.mp3 khi ghép
	Visible        bool    // hiện cửa sổ WV2 (debug). Default false.
	Voice          string  // voice ID (e.g. "21m00Tcm4TlvDq8ikWAM")
	Model          string  // model ID (e.g. "eleven_v3")
	LanguageCode   string  // "vi" / "en" / ...
	Speed          float64 // 0 → 1.0
	// Multilingual v2 — gửi kèm voice_settings (tts.go); model khác chỉ dùng speed.
	Stability       float64
	SimilarityBoost float64
	Style           float64
	UseSpeakerBoost bool
	Sitekey         string        // optional override hCaptcha sitekey
	Provider        ProxyProvider // bắt buộc
	Emit            EmitFn        // callback progress UI
	DataRoot        string        // root cho user-data-dir worker. Mặc định %LocalAppData%\ElevenFlow\wv2profiles
	// SharedProxyLease true = không trễ khởi động worker (Luna). false = trễ
	// i×400ms để worker 0 lease trước (nhiều dòng proxy / changeip).
	SharedProxyLease bool
	// ExportSRT true → gọi endpoint /stream/with-timestamps/anonymous để lấy
	// alignment ký tự (dựng SRT). Chỉ dùng ở mode 1 khối text.
	ExportSRT bool
}

// Pool điều phối N worker tiêu thụ chunks chia sẻ qua channel.
type Pool struct {
	cfg           Config
	proxyProvider ProxyProvider
	rotMu         sync.Mutex // dự trữ cho coalesce future per-worker rotation
	emitFn        EmitFn
	totalChunks   int
}

// Run thực thi 1 batch end-to-end:
//  1. Validate config
//  2. Chunk text
//  3. Spawn N goroutine worker (mỗi worker = LockOSThread + HWND + Chromium + LocalProxy)
//  4. Push chunks vào shared channel
//  5. Workers cạnh tranh tiêu thụ; 401 → rotate proxy + reopen WV2 + retry
//  6. Đợi tất cả xong → sort results theo chunk ID → trả
//
// PHẢI gọi từ regular goroutine — Pool sẽ tự LockOSThread cho từng worker.
func Run(ctx context.Context, text string, cfg Config) ([]ChunkResult, error) {
	cfg, err := prepareConfig(cfg)
	if err != nil {
		return nil, err
	}
	pieces := ChunkTextForTTS(text, cfg.MaxChars)
	if len(pieces) == 0 {
		return nil, fmt.Errorf("không có nội dung để xử lý")
	}
	chunks := make([]Chunk, len(pieces))
	for i, t := range pieces {
		outName := fmt.Sprintf("chunk_%04d.mp3", i)
		if stem := strings.TrimSpace(cfg.OutputFileStem); stem != "" {
			outName = fmt.Sprintf("%s_%04d.mp3", stem, i+1)
		}
		chunks[i] = Chunk{
			ID:         i,
			Text:       t,
			OutputPath: filepath.Join(cfg.OutputDir, outName),
		}
	}
	return executeChunks(ctx, chunks, cfg)
}

// RunChunks chạy pool trên danh sách chunk đã dựng sẵn (mode đa đoạn: chunk gắn
// GroupID theo đoạn, dùng chung 1 pool để tối đa hóa số luồng). Caller tự đặt
// ID (global, tăng dần liên tục), GroupID và OutputPath cho từng chunk.
func RunChunks(ctx context.Context, chunks []Chunk, cfg Config) ([]ChunkResult, error) {
	cfg, err := prepareConfig(cfg)
	if err != nil {
		return nil, err
	}
	if len(chunks) == 0 {
		return nil, fmt.Errorf("không có nội dung để xử lý")
	}
	return executeChunks(ctx, chunks, cfg)
}

// prepareConfig validate + điền mặc định + tạo thư mục output/data.
func prepareConfig(cfg Config) (Config, error) {
	if cfg.Provider == nil {
		return cfg, fmt.Errorf("ProxyProvider bắt buộc")
	}
	if cfg.NumWorkers < 1 {
		cfg.NumWorkers = 2
	}
	// MaxChars = trần cứng mỗi chunk (mặc định defaultMaxChunkChars).
	maxChunk := cfg.MaxChars
	if maxChunk <= 0 || maxChunk > defaultMaxChunkChars {
		maxChunk = defaultMaxChunkChars
	}
	cfg.MaxChars = maxChunk
	if cfg.Voice == "" || cfg.Model == "" {
		return cfg, fmt.Errorf("voice và model bắt buộc")
	}
	if cfg.LanguageCode == "" {
		cfg.LanguageCode = "en"
	}
	if err := ValidateLanguageForModel(cfg.Model, cfg.LanguageCode); err != nil {
		return cfg, err
	}
	if cfg.Speed <= 0 {
		cfg.Speed = 1.0
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = outputdir.BesideExecutable()
	}
	if cfg.DataRoot == "" {
		// TempDir thường nằm trên ổ có nhiều free space hơn LocalAppData; user
		// cũng quen với việc Temp tự dọn → ít risk filling C: khi batch lớn.
		cfg.DataRoot = filepath.Join(os.TempDir(), "elevenflow-wv2profiles")
	}
	if cfg.Emit == nil {
		cfg.Emit = func(int, int, string, string, int, int) {}
	}
	if err := os.MkdirAll(cfg.OutputDir, 0o700); err != nil {
		return cfg, fmt.Errorf("mkdir output: %w", err)
	}
	if err := os.MkdirAll(cfg.DataRoot, 0o700); err != nil {
		return cfg, fmt.Errorf("mkdir data root: %w", err)
	}
	return cfg, nil
}

// executeChunks chạy N worker tiêu thụ chung 1 channel chunks, gom kết quả
// (sort theo ID global). Dùng chung cho cả Run (1 khối text) và RunChunks (đa đoạn).
func executeChunks(ctx context.Context, chunks []Chunk, cfg Config) ([]ChunkResult, error) {
	// Disable GC trong scope batch: pkg/edge v1.0.22 + Go 1.26 + nhiều iframe
	// hCaptcha => crash trong parseVersion khi GC chạy sai lúc. Tắt GC rồi
	// restore khi batch xong. Memory peak ~vài chục MB / batch nên chấp nhận.
	prevGCPercent := debug.SetGCPercent(-1)
	defer func() {
		debug.SetGCPercent(prevGCPercent)
		runtime.GC()
		// Wipe toàn bộ DataRoot — mỗi spawn tạo dir unique (worker_<id>_<unix_nano>),
		// tích lũy nhiều dir nếu retry. Xóa ở batch boundary là sạch nhất.
		_ = os.RemoveAll(cfg.DataRoot)
		// Release lease + ngừng heartbeat khi batch xong (giải phóng key
		// cho user/worker khác lập tức, không phải đợi 90s zombie cleanup).
		if sd, ok := cfg.Provider.(interface{ Shutdown() }); ok {
			sd.Shutdown()
		}
	}()

	pool := &Pool{
		cfg:           cfg,
		proxyProvider: cfg.Provider,
		emitFn:        cfg.Emit,
		totalChunks:   len(chunks),
	}

	diaglog.Append("wv2_run_begin", map[string]any{
		"numChunks":   len(chunks),
		"numWorkers":  cfg.NumWorkers,
		"sharedLease": cfg.SharedProxyLease,
		"maxChars":    cfg.MaxChars,
	})

	chunkCh := make(chan Chunk, len(chunks))
	for _, c := range chunks {
		chunkCh <- c
	}
	close(chunkCh)

	resultCh := make(chan ChunkResult, len(chunks))
	var wg sync.WaitGroup

	pool.emit(-1, -1, "rotate",
		fmt.Sprintf("Đang xử lý %d dòng (tối đa ~%d ký tự mỗi đoạn)…",
			len(chunks), cfg.MaxChars),
		0, len(chunks))

	staggerMs := 0
	if cfg.NumWorkers > 1 && !cfg.SharedProxyLease {
		staggerMs = 400
	}
	for i := 0; i < cfg.NumWorkers; i++ {
		wg.Add(1)
		w := newWorker(i, pool, chunkCh, resultCh, cfg.DataRoot, cfg.Visible)
		startDelay := time.Duration(i) * time.Duration(staggerMs) * time.Millisecond
		go func(w *worker, delay time.Duration) {
			defer wg.Done()
			if delay > 0 {
				t := time.NewTimer(delay)
				select {
				case <-t.C:
				case <-ctx.Done():
					if !t.Stop() {
						<-t.C
					}
					return
				}
			}
			// Mỗi worker pin 1 OS thread (WV2 STA + COM init).
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if err := coInitializeApartment(); err != nil {
				pool.emit(w.id, -1, "error",
					"Không khởi tạo được môi trường Windows.",
					-1, pool.totalChunks)
				return
			}
			defer coUninitialize()
			w.run(ctx)
		}(w, startDelay)
	}

	// Goroutine collect results + drain chunks còn dư (nếu mọi worker exit
	// sớm vì spawn fail / disk full → chunks chưa consumed phải emit FAIL,
	// không để frontend treo chờ bằng 0 result).
	go func() {
		wg.Wait()
		drained := 0
		for chunk := range chunkCh {
			drained++
			diaglog.Append("wv2_drain_chunk", map[string]any{
				"chunkId": chunk.ID,
				"file":    filepath.Base(chunk.OutputPath),
			})
			resultCh <- ChunkResult{
				ID:       chunk.ID,
				GroupID:  chunk.GroupID,
				OK:       false,
				Message:  "không còn worker khả dụng (tất cả đã thoát do lỗi spawn / disk)",
				Output:   chunk.OutputPath,
				WorkerID: -1,
			}
		}
		if drained > 0 {
			diaglog.Append("wv2_drain_summary", map[string]any{"failedChunks": drained})
		}
		close(resultCh)
	}()

	doneCount := 0
	results := make([]ChunkResult, 0, len(chunks))
	for r := range resultCh {
		results = append(results, r)
		doneCount++
		phase := "done"
		if !r.OK {
			phase = "error"
		}
		pool.emit(r.WorkerID, r.ID, phase,
			fmt.Sprintf("Dòng %d/%d — %s",
				r.ID+1, len(chunks),
				FriendlyChunkSummary(r.OK, r.Message)),
			doneCount, len(chunks))
	}

	okN, failN := 0, 0
	for _, r := range results {
		if r.OK {
			okN++
		} else {
			failN++
		}
	}
	diaglog.Append("wv2_run_end", map[string]any{
		"chunks_ok": okN, "chunks_fail": failN, "total": len(results),
	})

	// Release leases (no-op cho SharedCurrentProvider).
	// Nếu sau này có per-worker provider, từng worker phải tự release trước khi exit.

	sort.SliceStable(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results, nil
}

// emit gửi tiến độ UI. done < 0 = chỉ log message, **không** cập nhật thanh %
// (tránh worker flood done=0 làm reset progress về 0).
func (p *Pool) emit(workerID, chunkID int, phase, message string, done, total int) {
	if p.emitFn != nil {
		p.emitFn(workerID, chunkID, phase, message, done, total)
	}
}

// requestFor build TTSRequest từ config + 1 chunk cụ thể. Chunk.Voice (nếu có)
// ghi đè Config.Voice — phục vụ mode hội thoại nhiều giọng trong cùng 1 pool.
func (p *Pool) requestFor(c Chunk) TTSRequest {
	voice := strings.TrimSpace(c.Voice)
	if voice == "" {
		voice = p.cfg.Voice
	}
	return TTSRequest{
		VoiceID:         voice,
		ModelID:         p.cfg.Model,
		LanguageCode:    p.cfg.LanguageCode,
		Text:            c.Text,
		Speed:           p.cfg.Speed,
		Stability:       p.cfg.Stability,
		SimilarityBoost: p.cfg.SimilarityBoost,
		Style:           p.cfg.Style,
		UseSpeakerBoost: p.cfg.UseSpeakerBoost,
		Sitekey:         p.cfg.Sitekey,
		ExportSRT:       p.cfg.ExportSRT,
	}
}
