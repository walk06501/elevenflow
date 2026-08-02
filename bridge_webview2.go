//go:build !camoufox

package main

import bridge "elevenflow/internal/webview2bridge"

// bridgeAlias re-exports cho app.go (build mặc định = WebView2).
// Khi build bình thường (không có tag), dùng webview2bridge.
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
