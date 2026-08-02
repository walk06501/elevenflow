//go:build windows

package webview2bridge

import (
	"os/exec"
	"syscall"
)

// prepareExecHideWindow — subprocess (ffmpeg) không mở cửa sổ console.
func prepareExecHideWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
}
