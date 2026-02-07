package trustinstall

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/truststore"
)

type fakeSystem struct {
	certsByCN map[string][]*x509.Certificate
	trusted   map[string]bool

	installCalls   []string
	trustCalls     []string
	uninstallCalls []string

	installErr   error
	trustErr     error
	uninstallErr error
}

func newFakeSystem() *fakeSystem {
	return &fakeSystem{
		certsByCN: make(map[string][]*x509.Certificate),
		trusted:   make(map[string]bool),
	}
}

func (f *fakeSystem) FindCertificatesByCommonName(commonName string) ([]systemCert, error) {
	var res []systemCert
	for _, c := range f.certsByCN[commonName] {
		res = append(res, systemCert{
			SHA1: sha1Hex(c),
			Cert: c,
		})
	}
	return res, nil
}

func (f *fakeSystem) IsCertTrusted(cert *x509.Certificate) (bool, error) {
	return f.trusted[sha1Hex(cert)], nil
}

func (f *fakeSystem) InstallCertFile(certFile string) error {
	f.installCalls = append(f.installCalls, certFile)
	if f.installErr != nil {
		return f.installErr
	}

	b, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	cert, err := parseCertificatePEM(b)
	if err != nil {
		return err
	}

	cn := cert.Subject.CommonName
	f.certsByCN[cn] = append(f.certsByCN[cn], cert)
	f.trusted[sha1Hex(cert)] = true
	return nil
}

func (f *fakeSystem) TrustCert(cert *x509.Certificate) error {
	f.trustCalls = append(f.trustCalls, sha1Hex(cert))
	if f.trustErr != nil {
		return f.trustErr
	}
	f.trusted[sha1Hex(cert)] = true
	return nil
}

func (f *fakeSystem) UninstallCert(cert *x509.Certificate) error {
	f.uninstallCalls = append(f.uninstallCalls, sha1Hex(cert))
	if f.uninstallErr != nil {
		return f.uninstallErr
	}

	cn := cert.Subject.CommonName
	sha1 := sha1Hex(cert)
	var kept []*x509.Certificate
	for _, c := range f.certsByCN[cn] {
		if !strings.EqualFold(sha1Hex(c), sha1) {
			kept = append(kept, c)
		}
	}
	f.certsByCN[cn] = kept
	delete(f.trusted, sha1)
	return nil
}

func TestGenerateSelfSignedCA(t *testing.T) {
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	cert, key, certPEM, keyPEM, err := generateSelfSignedCA("test-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA err=%v", err)
	}
	if cert == nil || key == nil {
		t.Fatalf("cert/key should not be nil")
	}
	if !cert.IsCA {
		t.Fatalf("expected IsCA=true")
	}
	if cert.Subject.CommonName != "test-ca" {
		t.Fatalf("unexpected CN=%q", cert.Subject.CommonName)
	}
	if cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != (x509.KeyUsageCertSign | x509.KeyUsageCRLSign) {
		t.Fatalf("unexpected KeyUsage=%v", cert.KeyUsage)
	}
	if !cert.NotBefore.Before(cert.NotAfter) {
		t.Fatalf("expected NotBefore < NotAfter, got %v >= %v", cert.NotBefore, cert.NotAfter)
	}
	if cert.NotAfter.Sub(now) < 365*24*time.Hour {
		t.Fatalf("expected long-lived cert, NotAfter=%v now=%v", cert.NotAfter, now)
	}
	// Must be able to verify it is self-signed.
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("expected self-signed signature to verify, err=%v", err)
	}
	if err := verifyKeyMatchesCert(key, cert); err != nil {
		t.Fatalf("verifyKeyMatchesCert err=%v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatalf("expected PEM outputs to be non-empty")
	}
}

func TestGenerateSelfSignedCA_InvalidArgs(t *testing.T) {
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	if _, _, _, _, err := generateSelfSignedCA("", now, rand.Reader); err == nil {
		t.Fatalf("expected error on empty commonName")
	}
	if _, _, _, _, err := generateSelfSignedCA("x", now, nil); err == nil {
		t.Fatalf("expected error on nil randReader")
	}
}

func TestValidateInputs_Invalid(t *testing.T) {
	cases := []struct {
		dir  string
		base string
		cn   string
	}{
		{"", "a", "cn"},
		{" ", "a", "cn"},
		{t.TempDir(), "", "cn"},
		{t.TempDir(), " ", "cn"},
		{t.TempDir(), "../a", "cn"},
		{t.TempDir(), "a/b", "cn"},
		{t.TempDir(), `a\\b`, "cn"},
		{t.TempDir(), "a", ""},
		{t.TempDir(), "a", " "},
	}

	for i, tc := range cases {
		if err := validateInputs(tc.dir, tc.base, tc.cn); err == nil {
			t.Fatalf("case %d expected error for dir=%q base=%q cn=%q", i, tc.dir, tc.base, tc.cn)
		}
	}
}

func TestParseCertificatePEM_Invalid(t *testing.T) {
	if _, err := parseCertificatePEM([]byte("not a pem")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestParsePrivateKeyPEM_ParsesRSAAndEC(t *testing.T) {
	// RSA PKCS#1
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey err=%v", err)
	}
	rb := x509.MarshalPKCS1PrivateKey(rk)
	rpem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: rb})
	s, err := parsePrivateKeyPEM(rpem)
	if err != nil {
		t.Fatalf("parsePrivateKeyPEM(RSA) err=%v", err)
	}
	if _, ok := s.(*rsa.PrivateKey); !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", s)
	}

	// EC SEC1
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey err=%v", err)
	}
	eb, err := x509.MarshalECPrivateKey(ek)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey err=%v", err)
	}
	epem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: eb})
	s, err = parsePrivateKeyPEM(epem)
	if err != nil {
		t.Fatalf("parsePrivateKeyPEM(EC) err=%v", err)
	}
	if _, ok := s.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", s)
	}

	// Unknown type
	if _, err := parsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "UNKNOWN", Bytes: []byte{1, 2, 3}})); err == nil {
		t.Fatalf("expected error on unknown pem type")
	}

	// Not a PEM
	if _, err := parsePrivateKeyPEM([]byte("not a pem")); err == nil {
		t.Fatalf("expected error on invalid pem")
	}
}

func TestVerifyKeyMatchesCert_NilArgs(t *testing.T) {
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	cert, key, _, _, err := generateSelfSignedCA("x", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA err=%v", err)
	}

	if err := verifyKeyMatchesCert(nil, cert); err == nil {
		t.Fatalf("expected error on nil key")
	}
	if err := verifyKeyMatchesCert(key, nil); err == nil {
		t.Fatalf("expected error on nil cert")
	}
}

func TestInstallCA_CreatesFilesAndInstallsWhenNotInstalled(t *testing.T) {
	tmp := t.TempDir()
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	sys := newFakeSystem()

	d := installDeps{
		now:        func() time.Time { return now },
		randReader: rand.Reader,
		sys:        sys,
	}

	if err := installCA(tmp, "my-ca", "my-ca", false, d); err != nil {
		t.Fatalf("installCA err=%v", err)
	}

	certFile, keyFile := caPaths(tmp, "my-ca")
	if _, err := os.Stat(certFile); err != nil {
		t.Fatalf("cert file stat err=%v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("key file stat err=%v", err)
	}

	if len(sys.installCalls) != 1 || sys.installCalls[0] != certFile {
		t.Fatalf("expected InstallCertFile called once with %q, got %v", certFile, sys.installCalls)
	}
}

func TestInstallCA_InstalledNotTrusted_CallsTrust(t *testing.T) {
	tmp := t.TempDir()
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	sys := newFakeSystem()

	caCert, caKey, certPEM, keyPEM, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA err=%v", err)
	}
	certFile, keyFile := caPaths(tmp, "my-ca")
	if err := writeCA(certFile, keyFile, certPEM, keyPEM); err != nil {
		t.Fatalf("writeCA err=%v", err)
	}

	sys.certsByCN[caCert.Subject.CommonName] = []*x509.Certificate{caCert}
	sys.trusted[sha1Hex(caCert)] = false

	d := installDeps{
		now:        func() time.Time { return now },
		randReader: rand.Reader,
		sys:        sys,
	}

	if err := installCA(tmp, "my-ca", "my-ca", false, d); err != nil {
		t.Fatalf("installCA err=%v", err)
	}
	if len(sys.installCalls) != 0 {
		t.Fatalf("expected no install calls, got %v", sys.installCalls)
	}
	if len(sys.trustCalls) != 1 {
		t.Fatalf("expected trust called once, got %v", sys.trustCalls)
	}
	if got := sys.trustCalls[0]; got != sha1Hex(caCert) {
		t.Fatalf("expected trust called for %s, got %s", sha1Hex(caCert), got)
	}

	_ = caKey
}

func TestInstallCA_InstalledTrusted_NoOps(t *testing.T) {
	tmp := t.TempDir()
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	sys := newFakeSystem()

	caCert, _, certPEM, keyPEM, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA err=%v", err)
	}
	certFile, keyFile := caPaths(tmp, "my-ca")
	if err := writeCA(certFile, keyFile, certPEM, keyPEM); err != nil {
		t.Fatalf("writeCA err=%v", err)
	}

	sys.certsByCN[caCert.Subject.CommonName] = []*x509.Certificate{caCert}
	sys.trusted[sha1Hex(caCert)] = true

	d := installDeps{
		now:        func() time.Time { return now },
		randReader: rand.Reader,
		sys:        sys,
	}

	if err := installCA(tmp, "my-ca", "my-ca", false, d); err != nil {
		t.Fatalf("installCA err=%v", err)
	}
	if len(sys.installCalls) != 0 || len(sys.trustCalls) != 0 || len(sys.uninstallCalls) != 0 {
		t.Fatalf("expected no ops, got install=%v trust=%v uninstall=%v", sys.installCalls, sys.trustCalls, sys.uninstallCalls)
	}
}

func TestInstallCA_DuplicateMismatched_DeleteSame(t *testing.T) {
	tmp := t.TempDir()
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	sys := newFakeSystem()

	wantCert, _, wantCertPEM, wantKeyPEM, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA want err=%v", err)
	}
	otherCert, _, _, _, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA other err=%v", err)
	}
	certFile, keyFile := caPaths(tmp, "my-ca")
	if err := writeCA(certFile, keyFile, wantCertPEM, wantKeyPEM); err != nil {
		t.Fatalf("writeCA err=%v", err)
	}

	sys.certsByCN["my-ca"] = []*x509.Certificate{wantCert, otherCert}
	sys.trusted[sha1Hex(wantCert)] = true

	d := installDeps{
		now:        func() time.Time { return now },
		randReader: rand.Reader,
		sys:        sys,
	}

	if err := installCA(tmp, "my-ca", "my-ca", true, d); err != nil {
		t.Fatalf("installCA err=%v", err)
	}
	if len(sys.uninstallCalls) != 1 {
		t.Fatalf("expected 1 uninstall call, got %v", sys.uninstallCalls)
	}
	if sys.uninstallCalls[0] == sha1Hex(wantCert) {
		t.Fatalf("should not uninstall desired cert")
	}
}

func TestInstallCA_DuplicateMismatched_NoDeleteSame(t *testing.T) {
	tmp := t.TempDir()
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	sys := newFakeSystem()

	wantCert, _, wantCertPEM, wantKeyPEM, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA want err=%v", err)
	}
	otherCert, _, _, _, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA other err=%v", err)
	}
	certFile, keyFile := caPaths(tmp, "my-ca")
	if err := writeCA(certFile, keyFile, wantCertPEM, wantKeyPEM); err != nil {
		t.Fatalf("writeCA err=%v", err)
	}

	sys.certsByCN["my-ca"] = []*x509.Certificate{wantCert, otherCert}
	sys.trusted[sha1Hex(wantCert)] = true

	d := installDeps{
		now:        func() time.Time { return now },
		randReader: rand.Reader,
		sys:        sys,
	}

	if err := installCA(tmp, "my-ca", "my-ca", false, d); err != nil {
		t.Fatalf("installCA err=%v", err)
	}
	if len(sys.uninstallCalls) != 0 {
		t.Fatalf("expected no uninstall calls, got %v", sys.uninstallCalls)
	}
}

func TestInstallCA_NotInstalledButHasMismatched_DeleteSame(t *testing.T) {
	tmp := t.TempDir()
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	sys := newFakeSystem()

	wantCert, _, wantCertPEM, wantKeyPEM, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA want err=%v", err)
	}
	otherCert, _, _, _, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA other err=%v", err)
	}
	certFile, keyFile := caPaths(tmp, "my-ca")
	if err := writeCA(certFile, keyFile, wantCertPEM, wantKeyPEM); err != nil {
		t.Fatalf("writeCA err=%v", err)
	}

	// system only has mismatched cert, but file is "want".
	sys.certsByCN["my-ca"] = []*x509.Certificate{otherCert}

	d := installDeps{
		now:        func() time.Time { return now },
		randReader: rand.Reader,
		sys:        sys,
	}

	if err := installCA(tmp, "my-ca", "my-ca", true, d); err != nil {
		t.Fatalf("installCA err=%v", err)
	}
	if len(sys.uninstallCalls) != 1 {
		t.Fatalf("expected 1 uninstall call, got %v", sys.uninstallCalls)
	}
	if len(sys.installCalls) != 1 {
		t.Fatalf("expected 1 install call, got %v", sys.installCalls)
	}
	if sys.installCalls[0] != certFile {
		t.Fatalf("expected install with %q, got %q", certFile, sys.installCalls[0])
	}

	// Should end up with desired cert trusted.
	found := false
	for _, c := range sys.certsByCN["my-ca"] {
		if strings.EqualFold(sha1Hex(c), sha1Hex(wantCert)) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected desired cert present in system")
	}
	if !sys.trusted[sha1Hex(wantCert)] {
		t.Fatalf("expected desired cert trusted")
	}
}

func TestInstallCA_InstallerCmdErrorIncludesOutput(t *testing.T) {
	tmp := t.TempDir()
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	sys := newFakeSystem()

	cmd := exec.Command("sudo", "security", "add-trusted-cert")
	sys.installErr = truststore.NewCmdError(errors.New("exit status 1"), cmd, []byte("sudo: a password is required"))

	d := installDeps{
		now:        func() time.Time { return now },
		randReader: rand.Reader,
		sys:        sys,
	}

	err := installCA(tmp, "need-sudo", "need-sudo", false, d)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "sudo: a password is required") {
		t.Fatalf("expected output included in error, got %v", err)
	}
}

func TestInstallCA_CommonNameSeparateFromFileBaseName(t *testing.T) {
	tmp := t.TempDir()
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	sys := newFakeSystem()

	d := installDeps{
		now:        func() time.Time { return now },
		randReader: rand.Reader,
		sys:        sys,
	}

	if err := installCA(tmp, "file-base", "cn-value", false, d); err != nil {
		t.Fatalf("installCA err=%v", err)
	}

	certFile, _ := caPaths(tmp, "file-base")
	b, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert err=%v", err)
	}
	cert, err := parseCertificatePEM(b)
	if err != nil {
		t.Fatalf("parse cert err=%v", err)
	}
	if cert.Subject.CommonName != "cn-value" {
		t.Fatalf("expected CN=%q got %q", "cn-value", cert.Subject.CommonName)
	}
}

func TestLoadCA_RejectsNonCA(t *testing.T) {
	tmp := t.TempDir()
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey err=%v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("rand serial err=%v", err)
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "leaf",
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate err=%v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey err=%v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	certFile := filepath.Join(tmp, "leaf.crt")
	keyFile := filepath.Join(tmp, "leaf.key")
	if err := writeCA(certFile, keyFile, certPEM, keyPEM); err != nil {
		t.Fatalf("writeCA err=%v", err)
	}

	if _, _, err := loadCA(certFile, keyFile); err == nil {
		t.Fatalf("expected loadCA to reject non-CA certificate")
	}
}

func TestLeafCertificate_ReadsCAFromFilesAndGeneratesLeaf(t *testing.T) {
	tmp := t.TempDir()
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)

	_, _, caCertPEM, caKeyPEM, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA err=%v", err)
	}
	certFile, keyFile := caPaths(tmp, "my-ca")
	if err := writeCA(certFile, keyFile, caCertPEM, caKeyPEM); err != nil {
		t.Fatalf("writeCA err=%v", err)
	}

	ti, err := New(Options{
		Dir:          tmp,
		FileBaseName: "my-ca",
		CommonName:   "my-ca",
	})
	if err != nil {
		t.Fatalf("New err=%v", err)
	}

	certPEM, keyPEM, err := ti.LeafCertificate("example.test")
	if err != nil {
		t.Fatalf("LeafCertificate err=%v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatalf("expected non-empty outputs")
	}
	certs, err := parseCertificatesFromPEM(certPEM)
	if err != nil {
		t.Fatalf("parseCertificatesFromPEM err=%v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected leaf+ca chain, got %d certs", len(certs))
	}
	leaf := certs[0]
	if leaf.Subject.CommonName != "example.test" {
		t.Fatalf("unexpected leaf CN=%q", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.test" {
		t.Fatalf("unexpected leaf DNSNames=%v", leaf.DNSNames)
	}
}

func TestGenerateLeafCertificate_SignedByCA(t *testing.T) {
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	caCert, caKey, _, _, err := generateSelfSignedCA("my-ca", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA err=%v", err)
	}

	certPEM, keyPEM, err := generateLeafCertificate("example.test", caCert, caKey, now, rand.Reader)
	if err != nil {
		t.Fatalf("generateLeafCertificate err=%v", err)
	}
	certs, err := parseCertificatesFromPEM(certPEM)
	if err != nil {
		t.Fatalf("parseCertificatesFromPEM err=%v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected leaf+ca chain, got %d certs", len(certs))
	}
	leaf := certs[0]
	if leaf.IsCA {
		t.Fatalf("expected leaf IsCA=false")
	}
	if err := leaf.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("expected leaf signature verified by CA, err=%v", err)
	}

	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("parsePrivateKeyPEM err=%v", err)
	}
	if err := verifyKeyMatchesCert(key, leaf); err != nil {
		t.Fatalf("verifyKeyMatchesCert err=%v", err)
	}
}

func TestLeafCertificate_InvalidHost(t *testing.T) {
	ti, err := New(Options{
		Dir:          t.TempDir(),
		FileBaseName: "my-ca",
		CommonName:   "my-ca",
	})
	if err != nil {
		t.Fatalf("New err=%v", err)
	}
	if _, _, err := ti.LeafCertificate(""); err == nil {
		t.Fatalf("expected error")
	}
}

func parseCertificatesFromPEM(b []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(b) > 0 {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
