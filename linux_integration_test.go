//go:build linux && (linux_integration || all_platform)

package trustinstall

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLinuxInstallUninstall_SystemTrust(t *testing.T) {
	// This test is meant to run inside a Linux container as root.
	// It performs real system trust store installation/uninstallation.

	tmp := t.TempDir()
	name := "trustinstall-it-" + strings.ReplaceAll(time.Now().UTC().Format("20060102-150405.000000000"), ".", "")
	t.Logf("dir=%s fileBaseName=%s commonName=%s", tmp, name, name)

	deleteSame := true
	ti, err := New(Options{
		Dir:          tmp,
		FileBaseName: name,
		CommonName:   name,
		DeleteSame:   &deleteSame,
	})
	if err != nil {
		t.Fatalf("New err=%v", err)
	}

	t.Logf("InstallCA: start")
	if err := ti.InstallCA(); err != nil {
		t.Fatalf("InstallCA err=%v", err)
	}
	t.Logf("InstallCA: done")

	// local files exist
	crtPath := filepath.Join(tmp, name+".crt")
	keyPath := filepath.Join(tmp, name+".key")
	if _, err := os.Stat(crtPath); err != nil {
		t.Fatalf("local crt stat err=%v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("local key stat err=%v", err)
	}
	t.Logf("local files: crt=%s key=%s", crtPath, keyPath)

	// system trust presence (best effort; scan based)
	sys, err := newSystemOps()
	if err != nil {
		t.Fatalf("newSystemOps err=%v", err)
	}
	caCert, err := loadLocalCACert(crtPath)
	if err != nil {
		t.Fatalf("loadLocalCACert err=%v", err)
	}

	// Some distros update trust store asynchronously; wait a bit.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := waitUntil(ctx, 500*time.Millisecond, func() (bool, error) {
		sysCerts, err := sys.FindCertificatesByCommonName(name)
		if err != nil {
			return false, err
		}
		t.Logf("system scan: found=%d", len(sysCerts))
		for i, c := range sysCerts {
			if c.Cert != nil {
				t.Logf("system[%d]: sha1=%s cn=%s", i, strings.TrimSpace(c.SHA1), strings.TrimSpace(c.Cert.Subject.CommonName))
			}
		}
		trusted, err := sys.IsCertTrusted(caCert)
		if err != nil {
			return false, err
		}
		t.Logf("IsCertTrusted=%v", trusted)
		return trusted, nil
	}); err != nil {
		t.Fatalf("wait system trust ready err=%v", err)
	}

	t.Logf("UninstallCA: start")
	res, err := ti.UninstallCA(true)
	if err != nil {
		t.Fatalf("UninstallCA err=%v", err)
	}
	t.Logf("UninstallCA: done deleted=%d certPath=%s keyPath=%s", res.Deleted, res.CertPath, res.KeyPath)

	// local files removed
	if _, err := os.Stat(crtPath); !os.IsNotExist(err) {
		t.Fatalf("local crt should be removed, stat err=%v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("local key should be removed, stat err=%v", err)
	}

	// wait until system cert is gone
	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel2()
	if err := waitUntil(ctx2, 500*time.Millisecond, func() (bool, error) {
		sysCerts, err := sys.FindCertificatesByCommonName(name)
		if err != nil {
			return false, err
		}
		t.Logf("after uninstall scan: found=%d", len(sysCerts))
		return len(sysCerts) == 0, nil
	}); err != nil {
		t.Fatalf("wait system cert removed err=%v", err)
	}
}

func loadLocalCACert(crtPath string) (*x509.Certificate, error) {
	b, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, err
	}
	return parseCertificatePEM(b)
}

func waitUntil(ctx context.Context, interval time.Duration, fn func() (bool, error)) error {
	for {
		ok, err := fn()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
