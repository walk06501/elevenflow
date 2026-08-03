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

		emit := func(workerID int, chunkID int, phase, message string, done, total int) {
			reqID := r.Header.Get("X-Request-Id")
			log.Printf("[%s] worker=%d chunk=%d phase=%s msg=%s (%d/%d)",
				reqID, workerID, chunkID, phase, message, done, total)
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
				r.Context(), req.Text, h.config.ChunkMaxChars, tmpDir, "output",
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
		pieces := webview2bridge.ChunkTextForTTS(req.Text, h.config.ChunkMaxChars)
		for _, cr := range chunkResults {
			if !cr.OK {
				allOK = false
				log.Printf("Chunk %d failed: %s", cr.ID, cr.Message)
			} else if cr.ID >= 0 && cr.ID < len(pieces) {
				charsUsed += utf8.RuneCountInString(pieces[cr.ID])
			}
		}

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

	inflight := cap(h.concurrencySem) - len(h.concurrencySem)

	resp := map[string]any{
		"status":          "ok",
		"workers_per_req": h.config.MaxWorkers,
		"max_concurrent":  h.config.MaxConcurrent,
		"inflight":        inflight,
		"proxy_pool_size": poolSize,
	}
	if h.sessionPool != nil {
		resp["persistent_pool_active_sessions"] = h.sessionPool.ActiveSessions()
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
	}

	result := make(map[string][]webview2bridge.LanguageOption)
	for _, m := range models {
		result[m] = webview2bridge.SupportedLanguagesForModel(m)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
