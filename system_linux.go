//go:build linux

package trustinstall

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/smallstep/truststore"
)

type linuxSystem struct{}

func newSystemOps() (systemOps, error) {
	// truststore will return ErrNotSupported if it cannot determine a system trust dir/command.
	return &linuxSystem{}, nil
}

func (s *linuxSystem) FindCertificatesByCommonName(commonName string) ([]systemCert, error) {
	dirs := linuxTrustDirs()
	if len(dirs) == 0 {
		return nil, truststore.ErrNotSupported
	}
	return scanCertificatesByCommonName(dirs, commonName)
}

func (s *linuxSystem) IsCertTrusted(cert *x509.Certificate) (bool, error) {
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

func (s *linuxSystem) InstallCertFile(certFile string) error {
	return truststore.InstallFile(certFile)
}

func (s *linuxSystem) TrustCert(cert *x509.Certificate) error {
	// On Linux, installing into the system trust store implies trust.
	// Keep method for interface compatibility.
	if cert == nil {
		return fmt.Errorf("证书为空")
	}
	return nil
}

func (s *linuxSystem) UninstallCert(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("证书为空")
	}
	return truststore.Uninstall(cert)
}

func linuxTrustDirs() []string {
	// Mirrors the directory detection order used by truststore (v0.13.0).
	candidates := []string{
		"/etc/pki/ca-trust/source/anchors/",
		"/usr/local/share/ca-certificates/",
		"/usr/share/pki/trust/anchors/",
		"/etc/ca-certificates/trust-source/anchors/",
		"/etc/ssl/certs/",
	}

	var dirs []string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			dirs = append(dirs, p)
		}
	}
	return dirs
}
