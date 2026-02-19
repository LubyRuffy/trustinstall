package trustinstall

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/smallstep/truststore"
)

type CertDuplicateStatus struct {
	CommonName string
	KeepSHA1   string
	SHA1s      []string
	KeepFound  bool
}

// CertTrustStatus reports whether the exact certificate file is installed and trusted by the OS.
func CertTrustStatus(certFile string) (installed bool, trusted bool, err error) {
	cert, err := readStatusCert(certFile)
	if err != nil {
		return false, false, err
	}
	sys, err := newSystemOpsFn()
	if err != nil {
		return false, false, err
	}
	return certTrustStatusWithSys(cert, sys)
}

// CertDuplicatesStatus reports same-CommonName certs and whether the given cert file exists in system store.
func CertDuplicatesStatus(certFile string) (CertDuplicateStatus, error) {
	cert, err := readStatusCert(certFile)
	if err != nil {
		return CertDuplicateStatus{}, err
	}
	sys, err := newSystemOpsFn()
	if err != nil {
		return CertDuplicateStatus{}, err
	}
	return certDuplicatesStatusWithSys(cert, sys)
}

// CleanupDuplicateTrustedCerts removes same-CommonName certs except the exact cert file.
//
// Safety:
//   - If keep cert is not present in system store, no deletion is performed.
//   - Deletion result is verified after cleanup.
func CleanupDuplicateTrustedCerts(certFile string) error {
	cert, err := readStatusCert(certFile)
	if err != nil {
		return err
	}
	sys, err := newSystemOpsFn()
	if err != nil {
		return err
	}
	return cleanupDuplicateTrustedCertsWithSys(cert, sys)
}

// EnsureCertInstalledAndTrusted installs cert file into system store and ensures it is trusted.
func EnsureCertInstalledAndTrusted(certFile string) error {
	cert, err := readStatusCert(certFile)
	if err != nil {
		return err
	}
	sys, err := newSystemOpsFn()
	if err != nil {
		return err
	}
	installed, trusted, err := certTrustStatusWithSys(cert, sys)
	if err != nil {
		return err
	}
	if !installed {
		if err := sys.InstallCertFile(certFile); err != nil {
			return wrapCmdError("安装证书到系统信任存储失败", err)
		}
		installed = true
	}
	if installed && trusted {
		return nil
	}
	if err := sys.TrustCert(cert); err != nil {
		return wrapCmdError("设置证书为始终信任失败", err)
	}
	return nil
}

func certTrustStatusWithSys(cert *x509.Certificate, sys systemOps) (installed bool, trusted bool, err error) {
	if cert == nil {
		return false, false, fmt.Errorf("证书为空")
	}
	if sys == nil {
		return false, false, fmt.Errorf("system ops 不能为空")
	}
	commonName := strings.TrimSpace(cert.Subject.CommonName)
	if commonName == "" {
		return false, false, fmt.Errorf("证书 CommonName 为空")
	}
	want := strings.TrimSpace(sha1Hex(cert))
	if want == "" {
		return false, false, fmt.Errorf("证书 SHA1 为空")
	}
	certs, err := sys.FindCertificatesByCommonName(commonName)
	if err != nil {
		return false, false, fmt.Errorf("查询系统证书失败: %w", err)
	}
	for _, certItem := range certs {
		if strings.EqualFold(systemCertSHA1(certItem), want) {
			installed = true
			break
		}
	}
	if !installed {
		return false, false, nil
	}
	trusted, err = sys.IsCertTrusted(cert)
	if err != nil {
		return true, false, fmt.Errorf("检查证书信任状态失败: %w", err)
	}
	return true, trusted, nil
}

func certDuplicatesStatusWithSys(cert *x509.Certificate, sys systemOps) (CertDuplicateStatus, error) {
	if cert == nil {
		return CertDuplicateStatus{}, fmt.Errorf("证书为空")
	}
	if sys == nil {
		return CertDuplicateStatus{}, fmt.Errorf("system ops 不能为空")
	}
	commonName := strings.TrimSpace(cert.Subject.CommonName)
	if commonName == "" {
		return CertDuplicateStatus{}, fmt.Errorf("证书 CommonName 为空")
	}
	keep := strings.TrimSpace(sha1Hex(cert))
	if keep == "" {
		return CertDuplicateStatus{}, fmt.Errorf("证书 SHA1 为空")
	}
	certs, err := sys.FindCertificatesByCommonName(commonName)
	if err != nil {
		return CertDuplicateStatus{}, fmt.Errorf("查询系统证书失败: %w", err)
	}

	seen := make(map[string]struct{}, len(certs))
	hashes := make([]string, 0, len(certs))
	keepFound := false
	for _, certItem := range certs {
		hash := systemCertSHA1(certItem)
		if hash == "" {
			continue
		}
		if _, ok := seen[hash]; ok {
			continue
		}
		seen[hash] = struct{}{}
		hashes = append(hashes, hash)
		if strings.EqualFold(hash, keep) {
			keepFound = true
		}
	}
	sort.Strings(hashes)

	return CertDuplicateStatus{
		CommonName: commonName,
		KeepSHA1:   keep,
		SHA1s:      hashes,
		KeepFound:  keepFound,
	}, nil
}

func cleanupDuplicateTrustedCertsWithSys(cert *x509.Certificate, sys systemOps) error {
	status, err := certDuplicatesStatusWithSys(cert, sys)
	if err != nil {
		return err
	}
	if len(status.SHA1s) <= 1 {
		return nil
	}
	if !status.KeepFound {
		// Keep cert not installed yet; avoid deleting stale certs before install succeeds.
		return nil
	}

	certs, err := sys.FindCertificatesByCommonName(status.CommonName)
	if err != nil {
		return fmt.Errorf("查询系统证书失败: %w", err)
	}
	var errs []error
	for _, certItem := range certs {
		hash := systemCertSHA1(certItem)
		if hash == "" || strings.EqualFold(hash, status.KeepSHA1) {
			continue
		}
		if certItem.Cert == nil {
			continue
		}
		if err := sys.UninstallCert(certItem.Cert); err != nil {
			errs = append(errs, wrapCmdError("删除系统中不一致的同名证书失败", err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	verify, err := certDuplicatesStatusWithSys(cert, sys)
	if err != nil {
		return err
	}
	if !verify.KeepFound {
		return fmt.Errorf("清理重复证书失败: keep 证书不存在")
	}
	if len(verify.SHA1s) != 1 {
		return fmt.Errorf("清理重复证书失败: remaining=%d", len(verify.SHA1s))
	}
	return nil
}

func readStatusCert(certFile string) (*x509.Certificate, error) {
	path := strings.TrimSpace(certFile)
	if path == "" {
		return nil, fmt.Errorf("certFile 不能为空")
	}
	cert, err := trustStoreReadCertificateFn(path)
	if err != nil {
		return nil, fmt.Errorf("读取证书失败: %w", err)
	}
	if cert == nil {
		return nil, fmt.Errorf("读取证书失败: 证书为空")
	}
	return cert, nil
}

var trustStoreReadCertificateFn = truststore.ReadCertificate
var newSystemOpsFn = newSystemOps

func systemCertSHA1(certItem systemCert) string {
	hash := strings.TrimSpace(certItem.SHA1)
	if hash != "" {
		return strings.ToUpper(hash)
	}
	if certItem.Cert == nil {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(sha1Hex(certItem.Cert)))
}
