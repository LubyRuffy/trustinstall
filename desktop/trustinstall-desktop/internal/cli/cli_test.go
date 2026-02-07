package cli

import "testing"

func TestParse_Defaults_NoInstallCA(t *testing.T) {
	t.Parallel()

	p, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse err: %v", err)
	}
	if p.InstallCA != nil {
		t.Fatalf("InstallCA should be nil")
	}
	if p.APIAddr == "" {
		t.Fatalf("APIAddr empty")
	}
	if p.APIFallbackPorts <= 0 {
		t.Fatalf("APIFallbackPorts=%d", p.APIFallbackPorts)
	}
}

func TestParse_InstallCA(t *testing.T) {
	t.Parallel()

	p, err := Parse([]string{
		"-install-ca",
		"-ca-dir", "~/.x",
		"-ca-name", "n",
		"-ca-common-name", "cn",
		"-delete-same=false",
	})
	if err != nil {
		t.Fatalf("Parse err: %v", err)
	}
	if p.InstallCA == nil {
		t.Fatalf("InstallCA nil")
	}
	if p.InstallCA.Dir != "~/.x" {
		t.Fatalf("Dir=%q", p.InstallCA.Dir)
	}
	if p.InstallCA.FileBaseName != "n" {
		t.Fatalf("FileBaseName=%q", p.InstallCA.FileBaseName)
	}
	if p.InstallCA.CommonName != "cn" {
		t.Fatalf("CommonName=%q", p.InstallCA.CommonName)
	}
	if p.InstallCA.DeleteSame {
		t.Fatalf("DeleteSame=true, want false")
	}
}

func TestParse_UninstallCA(t *testing.T) {
	t.Parallel()

	p, err := Parse([]string{
		"-uninstall-ca",
		"-ca-dir", "~/.x",
		"-ca-name", "n",
		"-ca-common-name", "cn",
		"-delete-local=false",
	})
	if err != nil {
		t.Fatalf("Parse err: %v", err)
	}
	if p.UninstallCA == nil {
		t.Fatalf("UninstallCA nil")
	}
	if p.UninstallCA.CommonName != "cn" {
		t.Fatalf("CommonName=%q", p.UninstallCA.CommonName)
	}
	if p.UninstallCA.DeleteLocal {
		t.Fatalf("DeleteLocal=true, want false")
	}
}
