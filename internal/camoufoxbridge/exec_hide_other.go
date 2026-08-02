//go:build !windows

package camoufoxbridge

import "os/exec"

func prepareExecHideWindow(*exec.Cmd) {}
