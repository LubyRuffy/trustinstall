package cli

import "testing"

func TestParse_DeleteSameFlag(t *testing.T) {
	t.Parallel()

	p, err := Parse([]string{
		"-install-ca",
		"-delete-same=false",
	})
	if err != nil {
		t.Fatalf("Parse err: %v", err)
	}
	if p.InstallCA == nil {
		t.Fatalf("InstallCA nil")
	}
	if p.InstallCA.DeleteSame {
		t.Fatalf("DeleteSame=true, want false")
	}
}

func TestParse_DeleteLocalFlag(t *testing.T) {
	t.Parallel()

	p, err := Parse([]string{
		"-uninstall-ca",
		"-delete-local=false",
	})
	if err != nil {
		t.Fatalf("Parse err: %v", err)
	}
	if p.UninstallCA == nil {
		t.Fatalf("UninstallCA nil")
	}
	if p.UninstallCA.DeleteLocal {
		t.Fatalf("DeleteLocal=true, want false")
	}
}
