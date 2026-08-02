package outputdir

import (
	"os"
	"path/filepath"
	"strings"
)

// BesideExecutable returns <directory of the running binary>/output.
// When the binary lives under a Go build temp dir (go run), uses <cwd>/output
// so audio is not written under %TEMP% by default.
func BesideExecutable() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(os.TempDir(), "elevenflow-out")
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		exe, _ = os.Executable()
	}
	dir := filepath.Dir(exe)
	if looksLikeEphemeralToolchainDir(dir) {
		if wd, err := os.Getwd(); err == nil {
			return filepath.Join(wd, "output")
		}
	}
	return filepath.Join(dir, "output")
}

func looksLikeEphemeralToolchainDir(dir string) bool {
	d := strings.ToLower(filepath.Clean(dir))
	if strings.Contains(d, "go-build") {
		return true
	}
	// Windows TEMP / macOS / Linux tmp
	if strings.Contains(d, string(filepath.Separator)+"tmp"+string(filepath.Separator)) {
		return true
	}
	if strings.Contains(d, `\temp\`) || strings.Contains(d, `/temp/`) {
		return true
	}
	return false
}
