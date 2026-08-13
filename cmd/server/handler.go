//go:build !camoufox

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"elevenflow/internal/buildinfo"
	"elevenflow/internal/proxyserver"
	"elevenflow/internal/subtitles"
	"elevenflow/internal/webview2bridge"
)

// Handler holds shared state for all HTTP endpoints.
type Handler struct {
	config         *Config
	proxyClient    *proxyserver.Client
	vpnProvider    webview2bridge.ProxyProvider // NordVPN today; built once in main.go, nil if no token configured
	sessionPool    *webview2bridge.SessionPool  // opt-in persistent pool (Config.UsePersistentPool); nil = use webview2bridge.Run per request as before
	concurrencySem chan struct{}                // Limits total inflight synthesis calls

	// progress: live done/total per in-flight request, keyed by the
	// caller's own JobID (req.JobID — same id already used for chunk
	// caching, see SynthesizeRequest.JobID doc comment). Exists because
	// /synthesize is a single blocking call for the whole request (up to
	// hundreds of internal chunks merged before responding) — the caller
	// (web-portal) otherwise has zero visibility into how far along a
	// long-running request is until it finishes entirely. Read via
	// GET /synthesize-progress?job_id=... (see HandleSynthesizeProgress),
	// written by HandleSynthesize's emit closure, deleted when that
	// request returns. Empty JobID (source never sends one, or an older
	// caller) means "don't bother tracking" — never populated, lookups on
	// "" simply miss, same as any other job_id nobody ever wrote.
	progress sync.Map // string (jobID) -> *progressState
}

// progressState is read by a DIFFERENT request's goroutine than the one
// writing it (HandleSynthesize's emit closure writes; HandleSynthesizeProgress
// reads), so every field access goes through mu — a raw struct swapped into
// the sync.Map would still race two goroutines reading/writing the SAME
// *progressState's fields concurrently once retrieved.
type progressState struct {
	mu      sync.Mutex
	done    int
	total   int
	message string
}

func (p *progressState) update(done, total int, message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// total arrives as -1 on some emit calls (see EmitFn doc comment) —
	// only overwrite once a real total is known, never regress back to
	// unknown. done is never sent as a real running count by any emit call
	// today (always -1 — see worker.go's call sites); the real "how many
	// chunks actually finished" signal is the "Xong dòng" message on a
	// phase=tts event with a real chunkID, detected by the caller (see
	// HandleSynthesize) rather than trusted from the done parameter itself.
	if total > 0 {
		p.total = total
	}
	if done > p.done {
		p.done = done
	}
	p.message = message
}

func (p *progressState) snapshot() (done, total int, message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.done, p.total, p.message
}

// SynthesizeRequest is the JSON body for POST /synthesize and /synthesize-srt.
// Mirrors GenerateParams from app.go but without GUI-specific fields.
type SynthesizeRequest struct {
	Text            string  `json:"text"`
	VoiceID         string  `json:"voice_id"`
	ModelID         string  `json:"model_id"`
	LanguageCode    string  `json:"language_code"`
	Speed           float64 `json:"speed"`
	Stability       float64 `json:"stability"`
	SimilarityBoost float64 `json:"similarity_boost"`
	Style           float64 `json:"style"`
	UseSpeakerBoost bool    `json:"use_speaker_boost"`
	ExportSRT       bool    `json:"export_srt"`
	MaxWorkers      int     `json:"max_workers"`
	// JobID (optional): the caller's own stable identifier for this piece of
	// text (web-portal sends its job_nodes.id, unchanged across that node's
	// own retries). When set and the persistent session pool is in use,
	// chunks that already succeeded on a PRIOR call with the same JobID are
	// served from cache instead of re-run — so a retry after one bad chunk
	// only redoes that chunk, not the whole text. Safe to omit: an empty
	// JobID just means every call is treated as independent (old behaviour).
	JobID string `json:"job_id"`
}

// SynthesizeSRTResponse is returned by /synthesize-srt endpoint.
type SynthesizeSRTResponse struct {
	AudioBase64 string `json:"audio_base64"`
	SRT         string `json:"srt"`
	CharsUsed   int    `json:"chars_used"`
}

// HandleSynthesize handles POST /synthesize (binary MP3 response) and
// POST /synthesize-srt (JSON with base64 audio + SRT).
//
// Flow mirrors app.go GenerateBatch() exactly:
//  1. Chunk text via webview2bridge.ChunkTextForTTS
//  2. Run synthesis pool via webview2bridge.Run
//  3. Merge chunks via webview2bridge.MergeChunks
//  4. Return merged audio (binary or base64)
func (h *Handler) HandleSynthesize(forceSRT bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		// Acquire concurrency slot (backpressure: wait up to 2 min or cancel)
		select {
		case h.concurrencySem <- struct{}{}:
			defer func() { <-h.concurrencySem }()
		case <-time.After(2 * time.Minute):
			http.Error(w, `{"error":"server busy, all synthesis slots occupied"}`, http.StatusServiceUnavailable)
			return
		case <-r.Context().Done():
			http.Error(w, `{"error":"request cancelled"}`, http.StatusRequestTimeout)
			return
		}

		// Parse request
		var req SynthesizeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"invalid json: %v"}`, err), http.StatusBadRequest)
			return
		}

		if req.Text == "" || req.VoiceID == "" || req.ModelID == "" {
			http.Error(w, `{"error":"text, voice_id, and model_id are required"}`, http.StatusBadRequest)
			return
		}

		if forceSRT {
			req.ExportSRT = true
		}

		// Resolve workers: strictly cap to 1 worker per request to keep CPU ultra low
		workers := h.config.MaxWorkers
		if req.MaxWorkers > 0 && req.MaxWorkers <= h.config.MaxWorkers {
			workers = req.MaxWorkers
		}

		// Create temp directory for this request's output files
		tmpDir, err := os.MkdirTemp(h.config.OutputDir, "req-*")
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"temp dir: %v"}`, err), http.StatusInternalServerError)
			return
		}
		defer os.RemoveAll(tmpDir) // Cleanup after response

		// completedChunks: distinct chunk IDs seen finishing successfully —
		// the ONLY reliable "how many actually done" signal available (see
		// progressState.update's doc comment: emit's own `done` parameter is
		// always -1 in every call site today). "Xong dòng" is worker.go's
		// exact success message (phase=tts, real chunkID, right before
		// returning res.OK=true) — matched by prefix rather than adding a
		// new EmitFn field, since EmitFn is shared with the Wails desktop
		// app's own progress UI and changing its shape would ripple there
		// for no benefit to that caller. A retried chunk fires this same
		// message again on eventual success; completedChunks is a set
		// specifically so a retry never double-counts.
		var progressMu sync.Mutex
		completedChunks := make(map[int]bool)
		emit := func(workerID int, chunkID int, phase, message string, done, total int) {
			reqID := r.Header.Get("X-Request-Id")
			log.Printf("[%s] worker=%d chunk=%d phase=%s msg=%s (%d/%d)",
				reqID, workerID, chunkID, phase, message, done, total)

			if req.JobID == "" {
				return
			}
			if phase == "tts" && chunkID >= 0 && strings.HasPrefix(message, "Xong dòng") {
				progressMu.Lock()
				completedChunks[chunkID] = true
				doneCount := len(completedChunks)
				progressMu.Unlock()
				ps, _ := h.progress.LoadOrStore(req.JobID, &progressState{})
				ps.(*progressState).update(doneCount, total, message)
			} else if total > 0 {
				// Not a completion event, but still worth recording the
				// real total + latest activity message as soon as it's
				// known (e.g. the very first "Đang tìm server..." rotate
				// event) — a caller polling before any chunk has finished
				// yet still sees a real total instead of nothing at all.
				ps, _ := h.progress.LoadOrStore(req.JobID, &progressState{})
				ps.(*progressState).update(-1, total, message)
			}
		}
		if req.JobID != "" {
			defer h.progress.Delete(req.JobID)
		}

		var chunkResults []webview2bridge.ChunkResult
		var synthErr error

		if h.sessionPool != nil {
			// Persistent pool path (Config.UsePersistentPool): reuses a fixed
			// set of already-open WebView2 sessions shared across every
			// request — see SessionPool's doc comment. No per-request
			// Provider/DataRoot here; the pool owns its own proxy provider
			// and browser-profile root for its whole lifetime.
			chunkResults, synthErr = h.sessionPool.Synthesize(
				r.Context(), req.JobID, req.Text, h.config.ChunkMaxChars, tmpDir, "output",
				webview2bridge.TTSParams{
					Model:           req.ModelID,
					LanguageCode:    req.LanguageCode,
					Speed:           req.Speed,
					Stability:       req.Stability,
					SimilarityBoost: req.SimilarityBoost,
					Style:           req.Style,
					UseSpeakerBoost: req.UseSpeakerBoost,
					ExportSRT:       req.ExportSRT,
				},
				req.VoiceID, emit,
			)
		} else {
			// Proxy provider: NordVPN (or, later, another VPN provider behind the
			// same ProxyProvider interface) exclusively when one is configured —
			// built once at startup, see main.go, never re-fetched or silently
			// swapped mid-request. The old pool provider is only reached here
			// when no VPN provider is configured at all (local/dev runs).
			provider := h.vpnProvider
			if provider == nil && h.proxyClient != nil {
				if buildinfo.SharedProxyLease {
					provider = webview2bridge.NewPoolProviderShared(h.proxyClient)
				} else {
					provider = webview2bridge.NewPoolProvider(h.proxyClient)
				}
			}

			// Build WebView2 bridge config — reuses the entire hCaptcha + ElevenLabs
			// pipeline from the desktop app
			cfg := webview2bridge.Config{
				NumWorkers:       workers,
				SharedProxyLease: buildinfo.SharedProxyLease,
				MaxChars:         h.config.ChunkMaxChars,
				OutputDir:        tmpDir,
				OutputFileStem:   "output",
				Voice:            req.VoiceID,
				Model:            req.ModelID,
				LanguageCode:     req.LanguageCode,
				Speed:            req.Speed,
				Stability:        req.Stability,
				SimilarityBoost:  req.SimilarityBoost,
				Style:            req.Style,
				UseSpeakerBoost:  req.UseSpeakerBoost,
				DataRoot:         filepath.Join(tmpDir, "wv2profiles"),
				ExportSRT:        req.ExportSRT,
				Provider:         provider,
				Emit:             emit,
			}

			// Run synthesis — this is the core call that spawns WebView2 instances,
			// solves hCaptcha, calls ElevenLabs API, and writes audio chunks
			chunkResults, synthErr = webview2bridge.Run(r.Context(), req.Text, cfg)
		}
		if synthErr != nil {
			http.Error(w, fmt.Sprintf(`{"error":"synthesis failed: %v"}`, synthErr), http.StatusInternalServerError)
			return
		}

		// Check all chunks succeeded
		allOK := len(chunkResults) > 0
		var charsUsed int
		var okCount, retriedCount, maxAttempt int
		var banRotates, networkRotates int
		var totalDurationMs, maxDurationMs int64
		pieces := webview2bridge.ChunkTextForTTS(req.Text, h.config.ChunkMaxChars)
		for _, cr := range chunkResults {
			if cr.Attempts > 1 {
				retriedCount++
			}
			if cr.Attempts > maxAttempt {
				maxAttempt = cr.Attempts
			}
			banRotates += cr.BanRotates
			networkRotates += cr.NetworkRotates
			totalDurationMs += cr.DurationMs
			if cr.DurationMs > maxDurationMs {
				maxDurationMs = cr.DurationMs
			}
			if !cr.OK {
				allOK = false
				log.Printf("Chunk %d failed: %s", cr.ID, cr.Message)
			} else {
				okCount++
				if cr.ID >= 0 && cr.ID < len(pieces) {
					charsUsed += utf8.RuneCountInString(pieces[cr.ID])
				}
			}
		}
		var avgDurationMs int64
		if len(chunkResults) > 0 {
			avgDurationMs = totalDurationMs / int64(len(chunkResults))
		}
		// Tổng kết cho việc phân tích sau: job_id có/không (bật cache hay
		// không), tỉ lệ chunk phải retry trong nội bộ 1 lần gọi này, attempt
		// cao nhất 1 chunk phải chịu, thời gian trung bình/chậm nhất 1 chunk,
		// và tỉ lệ rotate do bị chặn (ban) so với do mạng (network) — dữ liệu
		// để sau này tinh chỉnh stallTimeout/maxAttempts/weight từng VPN
		// provider (main.go) dựa trên số liệu thật thay vì đoán.
		log.Printf("[synth-summary] job_id=%q chunks=%d ok=%d retried=%d max_attempt=%d allOK=%v avg_ms=%d max_ms=%d ban_rotates=%d network_rotates=%d",
			req.JobID, len(chunkResults), okCount, retriedCount, maxAttempt, allOK, avgDurationMs, maxDurationMs, banRotates, networkRotates)

		if !allOK {
			// Collect first error message for diagnostics
			errMsg := "unknown"
			for _, cr := range chunkResults {
				if !cr.OK {
					errMsg = cr.Message
					break
				}
			}
			http.Error(w, fmt.Sprintf(`{"error":"chunk synthesis failed: %s"}`, errMsg), http.StatusInternalServerError)
			return
		}

		// Merge all chunks into a single MP3 (with 0.5s silence gaps if ffmpeg available)
		mergedPath := filepath.Join(tmpDir, "output.mp3")
		_, mergeErr := webview2bridge.MergeChunks(chunkResults, mergedPath)
		if mergeErr != nil {
			http.Error(w, fmt.Sprintf(`{"error":"merge failed: %v"}`, mergeErr), http.StatusInternalServerError)
			return
		}

		audioData, err := os.ReadFile(mergedPath)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"read audio: %v"}`, err), http.StatusInternalServerError)
			return
		}

		// SRT mode: return JSON with base64 audio + subtitle text
		if forceSRT {
			srtContent := h.buildSRT(chunkResults)
			resp := SynthesizeSRTResponse{
				AudioBase64: base64.StdEncoding.EncodeToString(audioData),
				SRT:         srtContent,
				CharsUsed:   charsUsed,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Normal mode: return binary MP3
		w.Header().Set("Content-Type", "audio/mpeg")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(audioData)))
		w.Write(audioData)
	}
}

// buildSRT generates SRT subtitle content from chunk alignment data.
// Ported from app.go writeMergedSRT().
func (h *Handler) buildSRT(results []webview2bridge.ChunkResult) string {
	gap := 0.0
	if webview2bridge.FindBundledFFmpeg() != "" {
		gap = 0.5
	}
	sorted := make([]webview2bridge.ChunkResult, len(results))
	copy(sorted, results)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	parts := make([]subtitles.Alignment, 0, len(sorted))
	for _, res := range sorted {
		parts = append(parts, res.Alignment)
	}
	merged := subtitles.MergeAlignments(parts, gap)
	if merged.Len() > 0 {
		srt, err := subtitles.BuildSRT(merged, subtitles.DefaultBuildOptions())
		if err == nil {
			return srt
		}
		log.Printf("buildSRT error: %v", err)
	}
	return ""
}

// HandleSynthesizeProgress handles GET /synthesize-progress?job_id=... — a
// caller with a long-running POST /synthesize in flight (up to hundreds of
// internal chunks, see Handler.progress doc comment) polls this from a
// SEPARATE request to see how far along it is, since /synthesize itself
// doesn't respond until the whole thing finishes. Same auth as every other
// route (AuthMiddleware wraps the whole mux, see main.go) — no extra check
// needed here.
//
// Always 200 with total=0 for an unknown/finished/never-tracked job_id
// (empty JobID on the original request, a job_id typo, or polling after the
// real request already returned and cleaned up its entry) rather than 404 —
// a caller polling in a loop shouldn't have to special-case "not found yet"
// vs "not found because it's over" vs "not found because there's a typo";
// total=0 reads the same as "nothing to report" in all three, and the
// caller already has the real terminal result from /synthesize's own
// response for the case that matters (did it actually succeed).
func (h *Handler) HandleSynthesizeProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	jobID := r.URL.Query().Get("job_id")
	w.Header().Set("Content-Type", "application/json")
	if jobID == "" {
		w.Write([]byte(`{"done":0,"total":0,"message":""}`))
		return
	}
	v, ok := h.progress.Load(jobID)
	if !ok {
		w.Write([]byte(`{"done":0,"total":0,"message":""}`))
		return
	}
	done, total, message := v.(*progressState).snapshot()
	json.NewEncoder(w).Encode(map[string]any{
		"done": done, "total": total, "message": message,
	})
}

// HandleHealth returns server health status and capacity info.
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Check proxy pool capacity if connected
	poolSize := 0
	if h.proxyClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		c, _, err := h.proxyClient.ProxyPoolCapacity(ctx)
		if err == nil {
			poolSize = c
		}
	}

	// Acquire pushes into concurrencySem, Release pops — len() is the count
	// currently held, i.e. the real inflight number (this was inverted
	// before: cap-len is the FREE slot count, not inflight, so an idle
	// server always read "inflight: max_concurrent").
	inflight := len(h.concurrencySem)

	resp := map[string]any{
		"status":          "ok",
		"workers_per_req": h.config.MaxWorkers,
		"max_concurrent":  h.config.MaxConcurrent,
		"inflight":        inflight,
		"proxy_pool_size": poolSize,
	}
	if h.sessionPool != nil {
		resp["persistent_pool_active_sessions"] = h.sessionPool.ActiveSessions()
		smallQ, bigQ, smallTotal, bigTotal := h.sessionPool.QueueStats()
		resp["queue_small_waiting"] = smallQ
		resp["queue_big_waiting"] = bigQ
		resp["queue_small_total"] = smallTotal
		resp["queue_big_total"] = bigTotal
	}
	// Per-VPN-source attempt/success/timing stats — only present when
	// multiple sources are configured (single-source setups skip the
	// MultiVPNProvider wrapper entirely, see main.go's vpnProvider switch).
	// Answers "which source actually fails or is actually slow more" as
	// opposed to "which source gets picked more often because of its
	// weight" — the two are easy to conflate from raw per-event log lines
	// alone under 20+-way concurrency.
	if mv, ok := h.vpnProvider.(*webview2bridge.MultiVPNProvider); ok {
		vpnStats := make(map[string]any)
		for name, st := range mv.Stats() {
			rate := 1.0
			avgMs := int64(0)
			if st.Attempts > 0 {
				rate = float64(st.Successes) / float64(st.Attempts)
			}
			if st.Successes > 0 {
				avgMs = st.TotalMs / st.Successes
			}
			vpnStats[name] = map[string]any{
				"attempts":     st.Attempts,
				"successes":    st.Successes,
				"success_rate": rate,
				"avg_ms":       avgMs,
				"max_ms":       st.MaxMs,
			}
		}
		resp["vpn_provider_stats"] = vpnStats
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandleModels returns supported ElevenLabs models with their language lists.
func (h *Handler) HandleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	models := []string{
		"eleven_v3",
		"eleven_multilingual_v2",
		"eleven_turbo_v2_5",
		"eleven_flash_v2_5",
		"eleven_turbo_v2",
		"eleven_flash_v2",
	}

	result := make(map[string][]webview2bridge.LanguageOption)
	for _, m := range models {
		result[m] = webview2bridge.SupportedLanguagesForModel(m)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
