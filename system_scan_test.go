package trustinstall

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScanCertificatesByCommonName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	c1, _, pem1, _, err := generateSelfSignedCA("cn-1", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA err=%v", err)
	}
	c2, _, pem2, _, err := generateSelfSignedCA("cn-2", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA err=%v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "a.crt"), pem1, 0o644); err != nil {
		t.Fatalf("write a.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.pem"), pem2, 0o644); err != nil {
		t.Fatalf("write b.pem: %v", err)
	}

	got, err := scanCertificatesByCommonName([]string{dir}, "cn-1")
	if err != nil {
		t.Fatalf("scan err=%v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d, want 1", len(got))
	}
	if got[0].Cert == nil || got[0].Cert.Subject.CommonName != c1.Subject.CommonName {
		t.Fatalf("unexpected cert CN=%v", got[0].Cert)
	}
	if got[0].SHA1 != sha1Hex(c1) {
		t.Fatalf("unexpected sha1=%q", got[0].SHA1)
	}

	got2, err := scanCertificatesByCommonName([]string{dir}, "cn-2")
	if err != nil {
		t.Fatalf("scan err=%v", err)
	}
	if len(got2) != 1 {
		t.Fatalf("len=%d, want 1", len(got2))
	}
	if got2[0].SHA1 != sha1Hex(c2) {
		t.Fatalf("unexpected sha1=%q", got2[0].SHA1)
	}
}
