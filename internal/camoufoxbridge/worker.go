package camoufoxbridge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"


	"elevenflow/internal/subtitles"
)

var (
	errUnusualActivity = errors.New("detected_unusual_activity")
	errTransient       = errors.New("transient_network_error")
)

// worker processes TTS chunks using Camoufox captcha solver + Go HTTP API client.
type worker struct {
	id           int
	pool         *Pool
	chunks       <-chan Chunk
	results      chan<- ChunkResult
	currentLease Lease
}

func newWorker(id int, pool *Pool, chunks <-chan Chunk, results chan<- ChunkResult) *worker {
	return &worker{
		id:      id,
		pool:    pool,
		chunks:  chunks,
		results: results,
	}
}

func (w *worker) run(ctx context.Context) {
	defer func() {
		if w.pool != nil && w.pool.proxyProvider != nil {
			w.pool.proxyProvider.Release(w.id, Lease{})
		}
	}()

	if err := w.acquireProxy(ctx); err != nil {
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
				return
			}
			res := w.processChunkWithRetry(ctx, chunk)
			select {
			case w.results <- res:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (w *worker) acquireProxy(ctx context.Context) error {
	lease, err := w.pool.proxyProvider.Acquire(ctx, w.id, func(msg string) {
		w.pool.emit(w.id, -1, "rotate", msg, -1, w.pool.totalChunks)
	})
	if err != nil {
		return fmt.Errorf("acquire proxy: %w", err)
	}
	w.currentLease = lease
	return nil
}

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
		if rotateErr := w.rotateProxy(ctx, chunk.ID, reason); rotateErr != nil {
			res.Message = rotateErr.Error()
			return res
		}
	}
	res.Message = "exhausted retries"
	return res
}

func (w *worker) rotateProxy(ctx context.Context, chunkID int, reason string) error {
	w.pool.emit(w.id, chunkID, "rotate",
		fmt.Sprintf("Đang đổi kết nối (%s)…", reason),
		-1, w.pool.totalChunks)

	oldLease := w.currentLease
	newLease, err := w.pool.proxyProvider.MarkUnhealthyAndRotate(ctx, w.id, oldLease, func(msg string) {
		w.pool.emit(w.id, chunkID, "rotate", msg, -1, w.pool.totalChunks)
	})
	if err != nil {
		return fmt.Errorf("rotate lỗi: %w", err)
	}
	w.currentLease = newLease
	return nil
}

func (w *worker) processChunkOnce(ctx context.Context, chunk Chunk) (subtitles.Alignment, error) {
	req := w.pool.requestFor(chunk)

	// Step 1: Solve hCaptcha via Camoufox.
	w.pool.emit(w.id, chunk.ID, "tts", "Đang giải captcha (Camoufox)…", -1, w.pool.totalChunks)

	token, err := solveCaptcha(ctx, w.currentLease.URL, req.Sitekey, func(msg string) {
		// Forward info messages from captcha solver.
		w.pool.emit(w.id, chunk.ID, "tts", msg, -1, w.pool.totalChunks)
	})
	if err != nil {
		errStr := err.Error()
		if isTransientCaptchaError(errStr) {
			return subtitles.Alignment{}, fmt.Errorf("%w: captcha: %s", errTransient, errStr)
		}
		return subtitles.Alignment{}, fmt.Errorf("captcha: %w", err)
	}

	w.pool.emit(w.id, chunk.ID, "tts",
		fmt.Sprintf("Token captcha OK (len=%d), đang gọi TTS API…", len(token)),
		-1, w.pool.totalChunks)

	// Step 2: Call ElevenLabs TTS API with the token.
	audio, align, err := callTTSAnonymous(ctx, req, token, w.currentLease.URL)
	if err != nil {
		var httpErr *ttsHTTPError
		if errors.As(err, &httpErr) {
			if httpErr.IsUnusualActivity() {
				return subtitles.Alignment{}, errUnusualActivity
			}
			if httpErr.IsTransient() {
				return subtitles.Alignment{}, fmt.Errorf("%w: HTTP %d: %s", errTransient, httpErr.Status, truncate(httpErr.Body, 200))
			}
		}
		errStr := err.Error()
		if isTransientNetworkError(errStr) {
			return subtitles.Alignment{}, fmt.Errorf("%w: %s", errTransient, errStr)
		}
		return subtitles.Alignment{}, err
	}

	// Step 3: Write audio to file.
	if err := os.WriteFile(chunk.OutputPath, audio, 0o644); err != nil {
		return subtitles.Alignment{}, fmt.Errorf("ghi file: %w", err)
	}

	return align, nil
}

func isTransientCaptchaError(s string) bool {
	low := strings.ToLower(s)
	markers := []string{
		"timeout", "network", "load failed", "api.js",
		"browser error", "connection", "expired",
	}
	for _, m := range markers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

func isTransientNetworkError(s string) bool {
	low := strings.ToLower(s)
	markers := []string{
		"failed to fetch", "networkerror", "network-error",
		"connection refused", "connection reset", "timeout",
		"i/o timeout", "eof", "broken pipe",
	}
	for _, m := range markers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}




