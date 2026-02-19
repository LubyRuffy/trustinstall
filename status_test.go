package trustinstall

import (
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertTrustStatusWithSys(t *testing.T) {
	cert, _ := mustSelfSignedCATestCert(t, "status-cn")
	fake := newFakeSystem()
	fake.certsByCN[cert.Subject.CommonName] = []*x509.Certificate{cert}
	fake.trusted[sha1Hex(cert)] = true

	installed, trusted, err := certTrustStatusWithSys(cert, fake)
	if err != nil {
		t.Fatalf("certTrustStatusWithSys err=%v", err)
	}
	if !installed || !trusted {
		t.Fatalf("expected installed/trusted=true, got installed=%v trusted=%v", installed, trusted)
	}
}

func TestCertTrustStatusWithSysNotInstalled(t *testing.T) {
	cert, _ := mustSelfSignedCATestCert(t, "status-not-installed")
	fake := newFakeSystem()

	installed, trusted, err := certTrustStatusWithSys(cert, fake)
	if err != nil {
		t.Fatalf("certTrustStatusWithSys err=%v", err)
	}
	if installed || trusted {
		t.Fatalf("expected installed/trusted=false, got installed=%v trusted=%v", installed, trusted)
	}
}

func TestCertDuplicatesStatusWithSys(t *testing.T) {
	keep, _ := mustSelfSignedCATestCert(t, "dup-cn")
	other, _ := mustSelfSignedCATestCert(t, "dup-cn")
	fake := newFakeSystem()
	fake.certsByCN[keep.Subject.CommonName] = []*x509.Certificate{keep, other}

	status, err := certDuplicatesStatusWithSys(keep, fake)
	if err != nil {
		t.Fatalf("certDuplicatesStatusWithSys err=%v", err)
	}
	if !status.KeepFound {
		t.Fatalf("expected KeepFound=true")
	}
	if len(status.SHA1s) != 2 {
		t.Fatalf("expected 2 hashes, got %d", len(status.SHA1s))
	}
}

func TestCleanupDuplicateTrustedCertsWithSys(t *testing.T) {
	keep, _ := mustSelfSignedCATestCert(t, "cleanup-cn")
	other, _ := mustSelfSignedCATestCert(t, "cleanup-cn")
	fake := newFakeSystem()
	fake.certsByCN[keep.Subject.CommonName] = []*x509.Certificate{keep, other}
	fake.trusted[sha1Hex(keep)] = true
	fake.trusted[sha1Hex(other)] = true

	if err := cleanupDuplicateTrustedCertsWithSys(keep, fake); err != nil {
		t.Fatalf("cleanupDuplicateTrustedCertsWithSys err=%v", err)
	}
	if len(fake.uninstallCalls) != 1 {
		t.Fatalf("expected 1 uninstall call, got %d", len(fake.uninstallCalls))
	}
	remaining := fake.certsByCN[keep.Subject.CommonName]
	if len(remaining) != 1 || !strings.EqualFold(sha1Hex(remaining[0]), sha1Hex(keep)) {
		t.Fatalf("expected only keep cert remaining")
	}
}

func TestEnsureCertInstalledAndTrusted(t *testing.T) {
	origNewSys := newSystemOpsFn
	defer func() { newSystemOpsFn = origNewSys }()

	cert, certPEM := mustSelfSignedCATestCert(t, "ensure-cn")
	certPath := writeTestCertFile(t, certPEM)

	fake := newFakeSystem()
	newSystemOpsFn = func() (systemOps, error) { return fake, nil }

	if err := EnsureCertInstalledAndTrusted(certPath); err != nil {
		t.Fatalf("EnsureCertInstalledAndTrusted err=%v", err)
	}
	if len(fake.installCalls) != 1 {
		t.Fatalf("expected 1 install call, got %d", len(fake.installCalls))
	}
	if len(fake.trustCalls) != 1 {
		t.Fatalf("expected 1 trust call after install, got %d", len(fake.trustCalls))
	}

	// installed but not trusted -> should call TrustCert only.
	fake2 := newFakeSystem()
	fake2.certsByCN[cert.Subject.CommonName] = []*x509.Certificate{cert}
	fake2.trusted[sha1Hex(cert)] = false
	newSystemOpsFn = func() (systemOps, error) { return fake2, nil }
	if err := EnsureCertInstalledAndTrusted(certPath); err != nil {
		t.Fatalf("EnsureCertInstalledAndTrusted trust path err=%v", err)
	}
	if len(fake2.installCalls) != 0 {
		t.Fatalf("expected 0 install call, got %d", len(fake2.installCalls))
	}
	if len(fake2.trustCalls) != 1 {
		t.Fatalf("expected 1 trust call, got %d", len(fake2.trustCalls))
	}
}

func TestPublicCertStatusAndCleanup(t *testing.T) {
	origNewSys := newSystemOpsFn
	defer func() { newSystemOpsFn = origNewSys }()

	keep, keepPEM := mustSelfSignedCATestCert(t, "public-cn")
	other, _ := mustSelfSignedCATestCert(t, "public-cn")
	certPath := writeTestCertFile(t, keepPEM)

	fake := newFakeSystem()
	fake.certsByCN[keep.Subject.CommonName] = []*x509.Certificate{keep, other}
	fake.trusted[sha1Hex(keep)] = true
	fake.trusted[sha1Hex(other)] = true
	newSystemOpsFn = func() (systemOps, error) { return fake, nil }

	installed, trusted, err := CertTrustStatus(certPath)
	if err != nil {
		t.Fatalf("CertTrustStatus err=%v", err)
	}
	if !installed || !trusted {
		t.Fatalf("expected installed/trusted=true, got installed=%v trusted=%v", installed, trusted)
	}

	status, err := CertDuplicatesStatus(certPath)
	if err != nil {
		t.Fatalf("CertDuplicatesStatus err=%v", err)
	}
	if !status.KeepFound || len(status.SHA1s) != 2 {
		t.Fatalf("unexpected duplicate status: keep=%v hashes=%d", status.KeepFound, len(status.SHA1s))
	}

	if err := CleanupDuplicateTrustedCerts(certPath); err != nil {
		t.Fatalf("CleanupDuplicateTrustedCerts err=%v", err)
	}
	if len(fake.uninstallCalls) != 1 {
		t.Fatalf("expected 1 uninstall call, got %d", len(fake.uninstallCalls))
	}
}

func mustSelfSignedCATestCert(t *testing.T, commonName string) (*x509.Certificate, []byte) {
	t.Helper()
	now := time.Date(2026, 2, 19, 10, 0, 0, 0, time.UTC)
	cert, _, certPEM, _, err := generateSelfSignedCA(commonName, now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA err=%v", err)
	}
	return cert, certPEM
}

func writeTestCertFile(t *testing.T, certPEM []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, certPEM, 0o644); err != nil {
		t.Fatalf("write cert file err=%v", err)
	}
	return path
}
