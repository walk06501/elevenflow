package main

import (
	"os"
	"strconv"
)

// Config holds all server configuration, loaded from environment variables.
type Config struct {
	Port           string // ELEVEN_SERVER_PORT: HTTP listen port (default: 8080)
	Secret         string // ELEVEN_SERVER_SECRET: API auth secret
	MaxWorkers     int    // ELEVEN_MAX_WORKERS: WebView2 instances per request (default: 3)
	MaxConcurrent  int    // ELEVEN_MAX_CONCURRENT: Total inflight synthesis requests (default: 50)
	OutputDir      string // ELEVEN_OUTPUT_DIR: Temp directory for audio output (default: ./output)
	ChunkMaxChars  int    // ELEVEN_CHUNK_MAX_CHARS: Max characters per chunk (default: 600)
	ServerURL      string // ELEVENFLOW_SERVER_URL: Proxy lease Vercel server
	AppSecret      string // ELEVENFLOW_APP_SECRET: Proxy lease auth secret
}

func LoadConfig() *Config {
	return &Config{
		Port:          getEnv("ELEVEN_SERVER_PORT", "8080"),
		Secret:        getEnv("ELEVEN_SERVER_SECRET", ""),
		MaxWorkers:    getEnvInt("ELEVEN_MAX_WORKERS", 3),
		MaxConcurrent: getEnvInt("ELEVEN_MAX_CONCURRENT", 50),
		OutputDir:     getEnv("ELEVEN_OUTPUT_DIR", "./output"),
		ChunkMaxChars: getEnvInt("ELEVEN_CHUNK_MAX_CHARS", 600),
		ServerURL:     getEnv("ELEVENFLOW_SERVER_URL", ""),
		AppSecret:     getEnv("ELEVENFLOW_APP_SECRET", ""),
	}
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		return fallback
	}
	v, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return v
}
