package cli

import "testing"

type stubUninstaller struct {
	calls []string
	n     int
	err   error
}

func (s *stubUninstaller) UninstallCA(dir, fileBaseName, commonName string, deleteLocal bool) (int, string, string, error) {
	s.calls = append(s.calls, commonName)
	return s.n, "", "", s.err
}

func TestRunUninstallCA_DefaultCommonName(t *testing.T) {
	t.Parallel()

	u := &stubUninstaller{n: 3}
	res, err := RunUninstallCA(u, UninstallCAOptions{})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if res.CommonName != "trustinstall-ca" {
		t.Fatalf("CommonName=%q", res.CommonName)
	}
	if res.Deleted != 3 {
		t.Fatalf("Deleted=%d", res.Deleted)
	}
}

func TestRunUninstallCA_DeleteLocal(t *testing.T) {
	t.Parallel()

	u := &stubUninstaller{n: 1}
	_, err := RunUninstallCA(u, UninstallCAOptions{
		CommonName:   "cn",
		DeleteLocal:  true,
		Dir:          "~/.x",
		FileBaseName: "a",
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
}
