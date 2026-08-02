package camoufoxbridge

import (
	"elevenflow/internal/subtitles"
)

// EmitFn receives progress events for UI display.
type EmitFn func(workerID int, chunkID int, phase, message string, done, total int)

// Chunk is one unit of TTS work assigned to one output file.
type Chunk struct {
	ID         int    // global index in batch (0-based)
	GroupID    int    // group (paragraph/segment) the chunk belongs to
	Voice      string // per-chunk voice ID override; empty = use Config.Voice
	Text       string // ≤ MaxChars characters
	OutputPath string // path to write .mp3
}

// ChunkResult summarizes one chunk after worker processes (or skips) it.
type ChunkResult struct {
	ID        int
	GroupID   int
	OK        bool
	Message   string
	Output    string
	Bytes     int64
	WorkerID  int
	Attempts  int
	Alignment subtitles.Alignment
}
