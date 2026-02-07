package trustinstall

import (
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type batchUninstallSystem struct {
	*fakeSystem
	batchCalls int
	lastN      int
}

func (s *batchUninstallSystem) EnsureUninstallCerts(certs []*x509.Certificate) error {
	s.batchCalls++
	s.lastN = len(certs)
	// Simulate deletion via the existing fake system logic.
	for _, c := range certs {
		_ = s.fakeSystem.UninstallCert(c)
	}
	return nil
}

func TestUninstallByCommonName_UsesBatchWhenAvailable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	wantCert, _, _, _, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA err=%v", err)
	}
	otherCert, _, _, _, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA other err=%v", err)
	}

	sys := &batchUninstallSystem{
		fakeSystem: newFakeSystem(),
	}
	sys.certsByCN["my-ca"] = []*x509.Certificate{wantCert, otherCert}

	n, err := uninstallByCommonName("my-ca", sys)
	if err != nil {
		t.Fatalf("uninstall err=%v", err)
	}
	if n != 2 {
		t.Fatalf("n=%d, want 2", n)
	}
	if sys.batchCalls != 1 {
		t.Fatalf("batchCalls=%d, want 1", sys.batchCalls)
	}
	if sys.lastN != 2 {
		t.Fatalf("lastN=%d, want 2", sys.lastN)
	}
}

func TestUninstallByCommonName_FallbackLoop(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	wantCert, _, _, _, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA err=%v", err)
	}
	otherCert, _, _, _, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA other err=%v", err)
	}

	sys := newFakeSystem()
	sys.certsByCN["my-ca"] = []*x509.Certificate{wantCert, otherCert}

	n, err := uninstallByCommonName("my-ca", sys)
	if err != nil {
		t.Fatalf("uninstall err=%v", err)
	}
	if n != 2 {
		t.Fatalf("n=%d, want 2", n)
	}
	if len(sys.uninstallCalls) != 2 {
		t.Fatalf("uninstallCalls=%v, want 2", sys.uninstallCalls)
	}
}

func TestUninstallCAWithSys_DeleteLocalFiles(t *testing.T) {
	t.Parallel()

	sys := newFakeSystem()
	// No system certs found; we only verify local file deletion behavior.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "a.crt")
	keyPath := filepath.Join(dir, "a.key")
	if err := os.WriteFile(certPath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	_, err := uninstallCAWithSys(dir, "a", "my-ca", true, sys, os.Remove)
	if err != nil {
		t.Fatalf("uninstallCAWithSys err=%v", err)
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Fatalf("cert should be removed, stat err=%v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("key should be removed, stat err=%v", err)
	}
}
