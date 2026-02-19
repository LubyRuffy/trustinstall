package trustinstall

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsCertCandidateFile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		want bool
	}{
		{name: "a.crt", want: true},
		{name: "a.pem", want: true},
		{name: "a.cer", want: true},
		{name: "a.der", want: true},
		{name: "f0a3b2c1.0", want: true},
		{name: "f0a3b2c1.12", want: true},
		{name: "a.txt", want: false},
		{name: "hash.x0", want: false},
		{name: "README", want: false},
		{name: "", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isCertCandidateFile(tc.name); got != tc.want {
				t.Fatalf("name=%q got=%v want=%v", tc.name, got, tc.want)
			}
		})
	}
}

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

func TestScanCertificatesByCommonName_HashStyleExt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	c1, _, pem1, _, err := generateSelfSignedCA("cn-hash", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA err=%v", err)
	}

	// Linux trust store often has symlinks/files with suffix like ".0", ".1".
	if err := os.WriteFile(filepath.Join(dir, "f0a3b2c1.0"), pem1, 0o644); err != nil {
		t.Fatalf("write hash cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.txt"), pem1, 0o644); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}

	got, err := scanCertificatesByCommonName([]string{dir}, "cn-hash")
	if err != nil {
		t.Fatalf("scan err=%v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d, want 1", len(got))
	}
	if got[0].SHA1 != sha1Hex(c1) {
		t.Fatalf("unexpected sha1=%q", got[0].SHA1)
	}
}
