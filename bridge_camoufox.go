//go:build camoufox

package main

import bridge "elevenflow/internal/camoufoxbridge"

// bridgeAlias re-exports cho app.go (build tag camoufox = dùng Camoufox).
type (
	BridgeConfig      = bridge.Config
	BridgeChunk       = bridge.Chunk
	BridgeChunkResult = bridge.ChunkResult
	BridgeEmitFn      = bridge.EmitFn
	BridgeProvider    = bridge.ProxyProvider
	BridgeLease       = bridge.Lease
)

var (
	BridgeRun                       = bridge.Run
	BridgeRunChunks                 = bridge.RunChunks
	BridgeChunkTextForTTS           = bridge.ChunkTextForTTS
	BridgeClampTTSSpeed             = bridge.ClampTTSSpeed
	BridgeSupportedLanguagesForModel = bridge.SupportedLanguagesForModel
	BridgeFindBundledFFmpeg         = bridge.FindBundledFFmpeg
	BridgeMergeChunks               = bridge.MergeChunks
	BridgeFriendlyChunkSummary      = bridge.FriendlyChunkSummary
	BridgeSplitParagraphs           = bridge.SplitParagraphs
	BridgeSplitDialogue             = bridge.SplitDialogue
	BridgeNewPoolProviderShared     = bridge.NewPoolProviderShared
	BridgeNewPoolProvider           = bridge.NewPoolProvider
)
