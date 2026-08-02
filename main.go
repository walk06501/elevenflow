package main

import (
	"embed"

	"elevenflow/internal/buildinfo"
	"elevenflow/internal/webview2bridge"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Create an instance of the app structure
	app := NewApp()

	// Bản "-fixed": nếu có WebView2 Runtime đóng gói cạnh exe, dùng nó cho cả
	// cửa sổ UI (để app mở được trên máy chưa cài WebView2 hệ thống).
	var winOpts *windows.Options
	if bp := webview2bridge.FindBundledWebView2(); bp != "" {
		winOpts = &windows.Options{WebviewBrowserPath: bp}
	}

	// Create application with options
	err := wails.Run(&options.App{
		Title:  "ElevenFlow",
		Width:  1040,
		Height: 720,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 15, G: 18, B: 28, A: 1},
		Debug: options.Debug{
			OpenInspectorOnStartup: buildinfo.Mode == "development",
		},
		OnStartup: app.startup,
		Windows:   winOpts,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
