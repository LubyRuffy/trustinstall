package trustinstall

import (
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

type ensureStubSystem struct {
	sysCerts []systemCert

	ensureCalls int
	ensureDelN  int

	installCalls int
	trustCalls   int
	uninstCalls  int
}

func (s *ensureStubSystem) FindCertificatesByCommonName(commonName string) ([]systemCert, error) {
	return s.sysCerts, nil
}

func (s *ensureStubSystem) IsCertTrusted(cert *x509.Certificate) (bool, error) {
	return false, nil
}

func (s *ensureStubSystem) InstallCertFile(certFile string) error {
	s.installCalls++
	return nil
}

func (s *ensureStubSystem) TrustCert(cert *x509.Certificate) error {
	s.trustCalls++
	return nil
}

func (s *ensureStubSystem) UninstallCert(cert *x509.Certificate) error {
	s.uninstCalls++
	return nil
}

func (s *ensureStubSystem) EnsureInstalledAndTrusted(certFile string, cert *x509.Certificate, deleteCerts []*x509.Certificate) error {
	s.ensureCalls++
	s.ensureDelN = len(deleteCerts)
	return nil
}

func TestInstallCA_EnsureBatchWhenAvailable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, _, cert, err := EnsureCAFiles(dir, "ca", "cn")
	if err != nil {
		t.Fatalf("EnsureCAFiles err=%v", err)
	}

	other, err := x509.ParseCertificate(cert.Raw)
	if err != nil {
		t.Fatalf("parse other err=%v", err)
	}
	other.SerialNumber = other.SerialNumber.Add(other.SerialNumber, other.SerialNumber) // just make it "different"

	sys := &ensureStubSystem{
		sysCerts: []systemCert{
			{SHA1: "DEADBEEF", Cert: other},
		},
	}

	err = installCA(dir, "ca", "cn", true, installDeps{
		now:        func() time.Time { return time.Now() },
		randReader: rand.Reader,
		sys:        sys,
	})
	if err != nil {
		t.Fatalf("installCA err=%v", err)
	}
	if sys.ensureCalls != 1 {
		t.Fatalf("ensureCalls=%d, want 1", sys.ensureCalls)
	}
	if sys.ensureDelN != 1 {
		t.Fatalf("ensureDelN=%d, want 1", sys.ensureDelN)
	}
	if sys.installCalls != 0 || sys.trustCalls != 0 || sys.uninstCalls != 0 {
		t.Fatalf("unexpected calls install=%d trust=%d uninst=%d", sys.installCalls, sys.trustCalls, sys.uninstCalls)
	}
}

func TestInstallCA_EnsureBatch_NoDeleteSame(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, _, cert, err := EnsureCAFiles(dir, "ca", "cn")
	if err != nil {
		t.Fatalf("EnsureCAFiles err=%v", err)
	}

	sys := &ensureStubSystem{
		// Pretend system has an unrelated cert with same CN; deleteSame=false should not pass it for deletion.
		sysCerts: []systemCert{
			{SHA1: "DEADBEEF", Cert: cert},
		},
	}

	err = installCA(dir, "ca", "cn", false, installDeps{
		now:        func() time.Time { return time.Now() },
		randReader: rand.Reader,
		sys:        sys,
	})
	if err != nil {
		t.Fatalf("installCA err=%v", err)
	}
	if sys.ensureCalls != 1 {
		t.Fatalf("ensureCalls=%d, want 1", sys.ensureCalls)
	}
	if sys.ensureDelN != 0 {
		t.Fatalf("ensureDelN=%d, want 0", sys.ensureDelN)
	}
}
