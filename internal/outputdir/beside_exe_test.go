package outputdir

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBesideExecutable_NotEmpty(t *testing.T) {
	d := BesideExecutable()
	if d == "" {
		t.Fatal("empty path")
	}
	if !strings.HasSuffix(filepath.ToSlash(strings.ToLower(d)), "/output") {
		t.Fatalf("expected .../output, got %q", d)
	}
}
