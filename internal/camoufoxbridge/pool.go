package camoufoxbridge

import (
	"context"
	"fmt"
	"os"

	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"elevenflow/internal/diaglog"
	"elevenflow/internal/outputdir"
)

const defaultMaxChunkChars = 600

// Config bundles runtime parameters for Pool.
type Config struct {
	NumWorkers      int
	MaxChars        int
	OutputDir       string
	OutputFileStem  string
	Visible         bool // ignored for Camoufox (always headless)
	Voice           string
	Model           string
	LanguageCode    string
	Speed           float64
	Stability       float64
	SimilarityBoost float64
	Style           float64
	UseSpeakerBoost bool
	Sitekey         string
	Provider        ProxyProvider
	Emit            EmitFn
	DataRoot        string // unused for Camoufox but kept for API compat
	SharedProxyLease bool
	ExportSRT       bool
}

// Pool orchestrates N workers consuming chunks from a shared channel.
type Pool struct {
	cfg           Config
	proxyProvider ProxyProvider
	emitFn        EmitFn
	totalChunks   int
}

// Run executes a batch end-to-end (single text block).
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

// RunChunks runs pool on pre-built chunk list (multi-paragraph mode).
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

func prepareConfig(cfg Config) (Config, error) {
	if cfg.Provider == nil {
		return cfg, fmt.Errorf("ProxyProvider bắt buộc")
	}
	if cfg.NumWorkers < 1 {
		cfg.NumWorkers = 2
	}
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
	if cfg.Emit == nil {
		cfg.Emit = func(int, int, string, string, int, int) {}
	}
	if err := os.MkdirAll(cfg.OutputDir, 0o700); err != nil {
		return cfg, fmt.Errorf("mkdir output: %w", err)
	}
	return cfg, nil
}

func executeChunks(ctx context.Context, chunks []Chunk, cfg Config) ([]ChunkResult, error) {
	defer func() {
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

	// Ensure browser (Chromium) is available before starting workers.
	pool.emit(-1, -1, "rotate", "Đang kiểm tra trình duyệt…", 0, len(chunks))
	if err := ensureBrowser(func(msg string) {
		pool.emit(-1, -1, "rotate", msg, -1, len(chunks))
	}); err != nil {
		return nil, fmt.Errorf("browser setup: %w", err)
	}

	diaglog.Append("cfox_run_begin", map[string]any{
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
		w := newWorker(i, pool, chunkCh, resultCh)
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
			// No LockOSThread needed — Camoufox runs as subprocess.
			w.run(ctx)
		}(w, startDelay)
	}

	// Drain unprocessed chunks if all workers exit early.
	go func() {
		wg.Wait()
		drained := 0
		for chunk := range chunkCh {
			drained++
			diaglog.Append("cfox_drain_chunk", map[string]any{
				"chunkId": chunk.ID,
				"file":    filepath.Base(chunk.OutputPath),
			})
			resultCh <- ChunkResult{
				ID:       chunk.ID,
				GroupID:  chunk.GroupID,
				OK:       false,
				Message:  "không còn worker khả dụng (tất cả đã thoát do lỗi)",
				Output:   chunk.OutputPath,
				WorkerID: -1,
			}
		}
		if drained > 0 {
			diaglog.Append("cfox_drain_summary", map[string]any{"failedChunks": drained})
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
	diaglog.Append("cfox_run_end", map[string]any{
		"chunks_ok": okN, "chunks_fail": failN, "total": len(results),
	})

	sort.SliceStable(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results, nil
}

func (p *Pool) emit(workerID, chunkID int, phase, message string, done, total int) {
	if p.emitFn != nil {
		p.emitFn(workerID, chunkID, phase, message, done, total)
	}
}

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


