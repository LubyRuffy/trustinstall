package cli

import (
	"path/filepath"
	"testing"
)

type stubInstaller struct {
	calls int
	last  struct {
		dir, fileBaseName, commonName string
		deleteSame                    bool
	}
	err error
}

func (s *stubInstaller) InstallCA(dir, fileBaseName, commonName string, deleteSame bool) error {
	s.calls++
	s.last.dir = dir
	s.last.fileBaseName = fileBaseName
	s.last.commonName = commonName
	s.last.deleteSame = deleteSame
	return s.err
}

func TestRunInstallCA_CallsOnce(t *testing.T) {
	t.Parallel()

	inst := &stubInstaller{}
	got, err := RunInstallCA(inst, InstallCAOptions{
		Dir:          "",
		FileBaseName: "",
		CommonName:   "",
		DeleteSame:   true,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if inst.calls != 1 {
		t.Fatalf("calls=%d, want 1", inst.calls)
	}
	if got.Attempts != 1 {
		t.Fatalf("Attempts=%d", got.Attempts)
	}
	if filepath.Base(got.CertPath) != "trustinstall-ca.crt" {
		t.Fatalf("CertPath=%q", got.CertPath)
	}
	if filepath.Base(got.KeyPath) != "trustinstall-ca.key" {
		t.Fatalf("KeyPath=%q", got.KeyPath)
	}
	if got.Dir == "" {
		t.Fatalf("Dir empty")
	}
}

func TestExpandDir_Tilde(t *testing.T) {
	t.Parallel()

	inst := &stubInstaller{}
	got, err := RunInstallCA(inst, InstallCAOptions{
		Dir:          "~/.trustinstall",
		FileBaseName: "a",
		CommonName:   "b",
		DeleteSame:   false,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if inst.calls != 1 {
		t.Fatalf("calls=%d, want 1", inst.calls)
	}
	if filepath.Base(got.Dir) != ".trustinstall" {
		t.Fatalf("Dir=%q", got.Dir)
	}
}
