//go:build linux && linux_integration

package trustinstall

import (
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

	if err := ti.InstallCA(); err != nil {
		t.Fatalf("InstallCA err=%v", err)
	}

	// local files exist
	if _, err := os.Stat(filepath.Join(tmp, name+".crt")); err != nil {
		t.Fatalf("local crt stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, name+".key")); err != nil {
		t.Fatalf("local key stat err=%v", err)
	}

	// system trust presence (best effort; scan based)
	sys, err := newSystemOps()
	if err != nil {
		t.Fatalf("newSystemOps err=%v", err)
	}
	sysCerts, err := sys.FindCertificatesByCommonName(name)
	if err != nil {
		t.Fatalf("FindCertificatesByCommonName err=%v", err)
	}
	if len(sysCerts) == 0 {
		t.Fatalf("expected system cert to be found by CN=%q", name)
	}

	res, err := ti.UninstallCA(true)
	if err != nil {
		t.Fatalf("UninstallCA err=%v", err)
	}
	if res.Deleted == 0 {
		t.Fatalf("expected Deleted > 0, got %d", res.Deleted)
	}

	// local files removed
	if _, err := os.Stat(filepath.Join(tmp, name+".crt")); !os.IsNotExist(err) {
		t.Fatalf("local crt should be removed, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, name+".key")); !os.IsNotExist(err) {
		t.Fatalf("local key should be removed, stat err=%v", err)
	}
}
