//go:build !camoufox

// Package main implements the elevenflow HTTP server — a headless version of
// the desktop app that exposes TTS synthesis via HTTP endpoints. Reuses the
// entire webview2bridge pipeline (WebView2 hCaptcha solving, proxy rotation,
// stealth scripts, ElevenLabs anonymous API calls) without any Wails dependency.
//
// Architecture:
//   Docker VPS (web portal worker) → HTTP POST /synthesize → This server
//   This server → WebView2 bridge → hCaptcha + ElevenLabs API → MP3 audio
//   This server → HTTP response (MP3 bytes) → Docker VPS worker
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"elevenflow/internal/proxyserver"
)

func main() {
	cfg := LoadConfig()

	// Ensure output directory exists for temp files
	if err := os.MkdirAll(cfg.OutputDir, 0o700); err != nil {
		log.Fatalf("Failed to create output directory %s: %v", cfg.OutputDir, err)
	}

	// Initialize proxy lease client — connects to existing Vercel backend
	// for atomic proxy pool management (same as desktop app's startup).
	var proxyClient *proxyserver.Client
	if cfg.ServerURL != "" && cfg.AppSecret != "" {
		proxyClient = proxyserver.New(cfg.ServerURL, cfg.AppSecret)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if proxyClient.HealthCheck(ctx) {
			log.Printf("Proxy server connected: %s", cfg.ServerURL)
		} else {
			log.Printf("Warning: proxy server health check failed for %s", cfg.ServerURL)
		}
		cancel()
	} else {
		log.Println("Warning: No proxy server configured (ELEVENFLOW_SERVER_URL / ELEVENFLOW_APP_SECRET)")
	}

	// Concurrency semaphore — hard cap on total inflight synthesis requests.
	// Each request uses MaxWorkers WebView2 instances, so actual browser
	// count peaks at MaxConcurrent × MaxWorkers.
	concurrencySem := make(chan struct{}, cfg.MaxConcurrent)

	// Register routes
	mux := http.NewServeMux()
	registerRoutes(mux, cfg, proxyClient, concurrencySem)

	// Apply middleware stack
	handler := WithMiddlewares(mux, cfg.Secret)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 5 * time.Minute, // Long timeout for synthesis
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		log.Printf("ElevenFlow server starting on :%s", cfg.Port)
		log.Printf("  MaxConcurrent: %d, MaxWorkers/req: %d, ChunkMax: %d chars",
			cfg.MaxConcurrent, cfg.MaxWorkers, cfg.ChunkMaxChars)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Graceful shutdown on SIGINT/SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server (waiting for inflight requests)...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Forced shutdown: %v", err)
	}
	log.Println("Server stopped.")
}

func registerRoutes(mux *http.ServeMux, cfg *Config, proxyClient *proxyserver.Client, concurrencySem chan struct{}) {
	h := &Handler{
		config:         cfg,
		proxyClient:    proxyClient,
		concurrencySem: concurrencySem,
	}
	mux.HandleFunc("/synthesize", h.HandleSynthesize(false))
	mux.HandleFunc("/synthesize-srt", h.HandleSynthesize(true))
	mux.HandleFunc("/health", h.HandleHealth)
	mux.HandleFunc("/models", h.HandleModels)
}
