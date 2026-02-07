//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGuessUTMWindowsVMIdentifierFromDisk(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { _ = os.Setenv("HOME", oldHome) })
	if err := os.Setenv("HOME", tmp); err != nil {
		t.Fatalf("set HOME: %v", err)
	}

	base := filepath.Join(tmp, "Library", "Containers", "com.utmapp.UTM", "Data", "Documents")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Put multiple candidates; should prefer ci-Windows.
	if err := os.MkdirAll(filepath.Join(base, "ci-windows.utm"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(base, "ci-Windows.utm"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	got := guessUTMWindowsVMIdentifierFromDisk()
	if got != "ci-Windows" {
		t.Fatalf("unexpected: %q", got)
	}
}
