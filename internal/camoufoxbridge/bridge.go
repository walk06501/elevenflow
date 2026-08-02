package camoufoxbridge

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// solverExeName is the PyInstaller-built captcha solver executable.
const solverExeName = "cfox_solver.exe"

// findSolver looks for cfox_solver.exe beside the main executable.
func findSolver() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot find executable path: %w", err)
	}
	exeDir := filepath.Dir(exe)

	// Try beside exe first.
	candidate := filepath.Join(exeDir, solverExeName)
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}

	// Try in tools/ subfolder.
	candidate = filepath.Join(exeDir, "tools", solverExeName)
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}

	// Try current working dir.
	if cwd, err := os.Getwd(); err == nil {
		candidate = filepath.Join(cwd, solverExeName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%s không tìm thấy (đặt cạnh file exe chính)", solverExeName)
}

// ensureBrowser verifies that cfox_solver.exe exists.
func ensureBrowser(emit func(string)) error {
	if emit == nil {
		emit = func(string) {}
	}
	path, err := findSolver()
	if err != nil {
		return err
	}
	emit(fmt.Sprintf("Solver: %s", filepath.Base(path)))
	return nil
}

// captchaRequest is the JSON sent to cfox_solver.exe stdin.
type captchaRequest struct {
	SiteURL  string `json:"site_url"`
	SiteKey  string `json:"site_key"`
	Proxy    string `json:"proxy,omitempty"`
	Headless bool   `json:"headless"`
}

// captchaResponse is a JSON line from cfox_solver.exe stdout.
type captchaResponse struct {
	Kind  string `json:"kind"`
	Msg   string `json:"msg,omitempty"`
	Token string `json:"token,omitempty"`
	Error string `json:"error,omitempty"`
}

// solveCaptcha runs cfox_solver.exe (compiled Camoufox Python) and returns the hCaptcha token.
// Pure exe — no Python needed on user machine.
func solveCaptcha(ctx context.Context, proxyURL, sitekey string, emit func(string)) (string, error) {
	if emit == nil {
		emit = func(string) {}
	}
	if sitekey == "" {
		sitekey = "8e58fe8c-1a48-4f94-88ae-8e90b586a192"
	}

	solverPath, err := findSolver()
	if err != nil {
		return "", err
	}

	// Build proxy string (strip http:// scheme).
	proxyStr := ""
	if proxyURL != "" {
		proxyStr = strings.TrimPrefix(proxyURL, "http://")
		proxyStr = strings.TrimPrefix(proxyStr, "https://")
	}

	req := captchaRequest{
		SiteURL:  "https://elevenlabs.io/",
		SiteKey:  sitekey,
		Proxy:    proxyStr,
		Headless: true,
	}
	reqJSON, _ := json.Marshal(req)

	// Run cfox_solver.exe
	cmd := exec.CommandContext(ctx, solverPath)
	cmd.Stderr = os.Stderr
	prepareExecHideWindow(cmd)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start solver: %w", err)
	}

	// Send request to stdin then close.
	_, _ = stdin.Write(reqJSON)
	_, _ = stdin.Write([]byte("\n"))
	_ = stdin.Close()

	// Read stdout JSON lines.
	var token string
	var lastError string
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var resp captchaResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			continue
		}
		switch resp.Kind {
		case "info":
			emit(resp.Msg)
		case "token":
			token = resp.Token
		case "error":
			lastError = resp.Error
		}
	}

	// Wait for process with timeout.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil && token == "" {
			if lastError != "" {
				return "", fmt.Errorf("solver: %s", lastError)
			}
			return "", fmt.Errorf("solver exit: %w", err)
		}
	case <-time.After(3 * time.Minute):
		_ = cmd.Process.Kill()
		return "", fmt.Errorf("solver timeout (3 min)")
	}

	if token == "" {
		if lastError != "" {
			return "", fmt.Errorf("solver: %s", lastError)
		}
		return "", fmt.Errorf("solver: no token")
	}

	return token, nil
}
