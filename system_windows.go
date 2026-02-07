//go:build windows

package trustinstall

import (
	"crypto/x509"
	"fmt"
	"os/exec"
	"strings"

	"github.com/smallstep/truststore"
)

type windowsSystem struct {
	execCmd func(name string, args ...string) *exec.Cmd
}

func newSystemOps() (systemOps, error) {
	return &windowsSystem{execCmd: exec.Command}, nil
}

func (s *windowsSystem) FindCertificatesByCommonName(commonName string) ([]systemCert, error) {
	cn := strings.TrimSpace(commonName)
	if cn == "" {
		return nil, fmt.Errorf("commonName 不能为空")
	}

	// Use PowerShell to enumerate LocalMachine Root store and include raw bytes.
	// This keeps implementation self-contained and avoids custom syscall bindings here.
	script := `$ErrorActionPreference='Stop'; ` +
		`Get-ChildItem -Path Cert:\LocalMachine\Root | ` +
		`ForEach-Object { ` +
		`$cn=''; if ($_.Subject -match 'CN=([^,]+)') { $cn=$matches[1] }; ` +
		`[PSCustomObject]@{Thumbprint=$_.Thumbprint; CommonName=$cn; RawBase64=[Convert]::ToBase64String($_.RawData)} ` +
		`} | ConvertTo-Json -Compress`

	cmd := s.execCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, truststore.NewCmdError(err, cmd, out)
	}

	items, err := parseWindowsCertItemsJSON(out)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var res []systemCert
	for _, it := range items {
		if !strings.EqualFold(strings.TrimSpace(it.CommonName), cn) {
			continue
		}
		raw, err := decodeWindowsRawCert(it.RawBase64)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(raw)
		if err != nil || cert == nil {
			continue
		}
		sha1 := normalizeThumbprint(it.Thumbprint)
		if sha1 == "" {
			sha1 = sha1Hex(cert)
		}
		if sha1 == "" || seen[sha1] {
			continue
		}
		seen[sha1] = true
		res = append(res, systemCert{SHA1: sha1, Cert: cert})
	}

	return res, nil
}

func (s *windowsSystem) IsCertTrusted(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, fmt.Errorf("证书为空")
	}
	cn := strings.TrimSpace(cert.Subject.CommonName)
	if cn == "" {
		return false, fmt.Errorf("证书 CommonName 为空")
	}
	sysCerts, err := s.FindCertificatesByCommonName(cn)
	if err != nil {
		return false, err
	}
	want := sha1Hex(cert)
	for _, c := range sysCerts {
		if strings.EqualFold(strings.TrimSpace(c.SHA1), want) {
			return true, nil
		}
	}
	return false, nil
}

func (s *windowsSystem) InstallCertFile(certFile string) error {
	return truststore.InstallFile(certFile)
}

func (s *windowsSystem) TrustCert(cert *x509.Certificate) error {
	// On Windows, installing into ROOT store implies trust.
	if cert == nil {
		return fmt.Errorf("证书为空")
	}
	return nil
}

func (s *windowsSystem) UninstallCert(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("证书为空")
	}
	return truststore.Uninstall(cert)
}
