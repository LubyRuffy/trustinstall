package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type stubInstaller struct {
	calls []installCall
	err   error

	uninstallArgs []struct {
		dir, fileBaseName, commonName string
		deleteLocal                   bool
	}
	uninstallErr error
}

type installCall struct {
	dir, fileBaseName, commonName string
	deleteSame                    bool
}

func (s *stubInstaller) InstallCA(dir, fileBaseName, commonName string, deleteSame bool) error {
	s.calls = append(s.calls, installCall{
		dir:          dir,
		fileBaseName: fileBaseName,
		commonName:   commonName,
		deleteSame:   deleteSame,
	})
	return s.err
}

func (s *stubInstaller) UninstallCA(dir, fileBaseName, commonName string, deleteLocal bool) (int, string, string, error) {
	s.uninstallArgs = append(s.uninstallArgs, struct {
		dir, fileBaseName, commonName string
		deleteLocal                   bool
	}{dir: dir, fileBaseName: fileBaseName, commonName: commonName, deleteLocal: deleteLocal})
	if s.uninstallErr != nil {
		return 0, "", "", s.uninstallErr
	}
	return 0, "", "", nil
}

func TestInstallCA_Defaults(t *testing.T) {
	t.Parallel()

	inst := &stubInstaller{}
	h := newRouter(inst)

	body, _ := json.Marshal(map[string]any{
		"dir":          "",
		"fileBaseName": "",
		"commonName":   "",
		"deleteSame":   true,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/installca", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(inst.calls) != 1 {
		t.Fatalf("calls=%d, want 1", len(inst.calls))
	}
	c := inst.calls[0]
	if c.dir == "" {
		t.Fatalf("dir empty")
	}
	if c.fileBaseName != "trustinstall-ca" {
		t.Fatalf("fileBaseName=%q", c.fileBaseName)
	}
	if c.commonName != "trustinstall-ca" {
		t.Fatalf("commonName=%q", c.commonName)
	}
	if !c.deleteSame {
		t.Fatalf("deleteSame=false, want true")
	}

	var resp installCAResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.OK {
		t.Fatalf("ok=false")
	}
	if resp.Attempts != 1 {
		t.Fatalf("attempts=%d", resp.Attempts)
	}
	if filepath.Base(resp.CertPath) != "trustinstall-ca.crt" {
		t.Fatalf("certPath=%q", resp.CertPath)
	}
	if filepath.Base(resp.KeyPath) != "trustinstall-ca.key" {
		t.Fatalf("keyPath=%q", resp.KeyPath)
	}
}

func TestInstallCA_Error(t *testing.T) {
	t.Parallel()

	inst := &stubInstaller{err: errTest}
	h := newRouter(inst)

	body, _ := json.Marshal(map[string]any{
		"dir":          "/tmp/x",
		"fileBaseName": "a",
		"commonName":   "b",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/installca", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestInstallCA_CommonNameChanged_RecreateLocalFiles(t *testing.T) {
	t.Parallel()

	inst := &stubInstaller{}
	h := newRouter(inst)

	dir := t.TempDir()
	// 写入一个旧 CN 的证书（最小自签名 CA），用于触发“CN 变化自动删除”.
	certPath := filepath.Join(dir, "trustinstall-ca.crt")
	keyPath := filepath.Join(dir, "trustinstall-ca.key")
	if err := os.WriteFile(certPath, []byte(testCACertPEM("old-cn")), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"dir":          dir,
		"fileBaseName": "trustinstall-ca",
		"commonName":   "new-cn",
		"deleteSame":   false,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/installca", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(inst.calls) != 1 {
		t.Fatalf("calls=%d, want 1", len(inst.calls))
	}
	if inst.calls[0].commonName != "new-cn" {
		t.Fatalf("commonName=%q", inst.calls[0].commonName)
	}

	// 旧文件应该被删除（stubInstaller 不会重建文件）。
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Fatalf("cert should be removed, stat err=%v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("key should be removed, stat err=%v", err)
	}
}

var errTest = &testError{s: "boom"}

type testError struct{ s string }

func (e *testError) Error() string { return e.s }

func testCACertPEM(cn string) string {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ""
	}
	now := time.Now().Add(-time.Minute)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
