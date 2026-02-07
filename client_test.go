package trustinstall

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestNew_DefaultsAndExpandTilde(t *testing.T) {
	t.Parallel()

	ti, err := New(Options{Dir: "~/.trustinstall"})
	if err != nil {
		t.Fatalf("New err=%v", err)
	}
	if !strings.Contains(ti.Dir(), ".trustinstall") {
		t.Fatalf("Dir=%q", ti.Dir())
	}
	if ti.FileBaseName() != "trustinstall-ca" {
		t.Fatalf("FileBaseName=%q", ti.FileBaseName())
	}
	if ti.CommonName() != "trustinstall-ca" {
		t.Fatalf("CommonName=%q", ti.CommonName())
	}
	if !ti.DeleteSame() {
		t.Fatalf("DeleteSame=false, want true")
	}
}

func TestClient_LeafCertificate_UsesConfiguredPaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, _, _, err := EnsureCAFiles(dir, "my-ca", "my-ca")
	if err != nil {
		t.Fatalf("EnsureCAFiles err=%v", err)
	}

	ti, err := New(Options{
		Dir:          dir,
		FileBaseName: "my-ca",
		CommonName:   "my-ca",
	})
	if err != nil {
		t.Fatalf("New err=%v", err)
	}

	certPEM, _, err := ti.LeafCertificate("example.com")
	if err != nil {
		t.Fatalf("LeafCertificate err=%v", err)
	}
	// LeafCertificate returns leaf + CA chain, so it must contain at least 2 cert blocks.
	n := 0
	for {
		var b *pem.Block
		b, certPEM = pem.Decode(certPEM)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			n++
			if _, err := x509.ParseCertificate(b.Bytes); err != nil {
				t.Fatalf("parse cert err=%v", err)
			}
		}
	}
	if n < 2 {
		t.Fatalf("cert blocks=%d, want >=2", n)
	}
}
