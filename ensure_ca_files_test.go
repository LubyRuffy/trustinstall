package trustinstall

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureCAFiles_GenerateAndReuse(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, keyPath, cert, err := EnsureCAFiles(dir, "test-ca", "test-ca")
	if err != nil {
		t.Fatalf("EnsureCAFiles err=%v", err)
	}
	if cert == nil {
		t.Fatalf("cert should not be nil")
	}
	if !cert.IsCA {
		t.Fatalf("expected IsCA=true")
	}
	if filepath.Base(certPath) != "test-ca.crt" {
		t.Fatalf("certPath=%q", certPath)
	}
	if filepath.Base(keyPath) != "test-ca.key" {
		t.Fatalf("keyPath=%q", keyPath)
	}

	certBytes1, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyBytes1, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	certPath2, keyPath2, cert2, err := EnsureCAFiles(dir, "test-ca", "test-ca")
	if err != nil {
		t.Fatalf("EnsureCAFiles(reuse) err=%v", err)
	}
	if cert2 == nil {
		t.Fatalf("cert2 should not be nil")
	}
	if cert2.Subject.CommonName != "test-ca" {
		t.Fatalf("CN=%q", cert2.Subject.CommonName)
	}
	if certPath2 != certPath || keyPath2 != keyPath {
		t.Fatalf("paths changed: %q/%q -> %q/%q", certPath, keyPath, certPath2, keyPath2)
	}

	certBytes2, err := os.ReadFile(certPath2)
	if err != nil {
		t.Fatalf("read cert2: %v", err)
	}
	keyBytes2, err := os.ReadFile(keyPath2)
	if err != nil {
		t.Fatalf("read key2: %v", err)
	}
	if !bytes.Equal(certBytes1, certBytes2) {
		t.Fatalf("cert bytes changed on reuse")
	}
	if !bytes.Equal(keyBytes1, keyBytes2) {
		t.Fatalf("key bytes changed on reuse")
	}
}
