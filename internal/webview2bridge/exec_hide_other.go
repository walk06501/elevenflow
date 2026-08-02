//go:build !windows

package webview2bridge

import "os/exec"

func prepareExecHideWindow(*exec.Cmd) {}
