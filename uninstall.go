package trustinstall

import (
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"
)

type UninstallCAResult struct {
	Deleted  int
	CertPath string
	KeyPath  string
}

func uninstallByCommonName(commonName string, sys systemOps) (int, error) {
	cn := strings.TrimSpace(commonName)
	if cn == "" {
		return 0, fmt.Errorf("commonName 不能为空")
	}

	certs, err := sys.FindCertificatesByCommonName(cn)
	if err != nil {
		return 0, fmt.Errorf("查询系统证书失败: %w", err)
	}

	var targets []*x509.Certificate
	for _, c := range certs {
		if c.Cert != nil {
			targets = append(targets, c.Cert)
		}
	}
	if len(targets) == 0 {
		return 0, nil
	}

	if bat, ok := sys.(interface {
		EnsureUninstallCerts(certs []*x509.Certificate) error
	}); ok {
		if err := bat.EnsureUninstallCerts(targets); err != nil {
			return len(targets), err
		}
		return len(targets), nil
	}

	for _, c := range targets {
		if err := sys.UninstallCert(c); err != nil {
			return len(targets), wrapCmdError("删除系统证书失败", err)
		}
	}
	return len(targets), nil
}

func uninstallCAWithSys(dir, fileBaseName, commonName string, deleteLocal bool, sys systemOps, remove func(string) error) (UninstallCAResult, error) {
	cn := strings.TrimSpace(commonName)
	if cn == "" {
		return UninstallCAResult{}, fmt.Errorf("commonName 不能为空")
	}

	deleted, err := uninstallByCommonName(cn, sys)
	if err != nil {
		return UninstallCAResult{}, err
	}

	var certPath, keyPath string
	if deleteLocal {
		if strings.TrimSpace(dir) == "" {
			return UninstallCAResult{}, fmt.Errorf("dir 不能为空（deleteLocal=true）")
		}
		if strings.TrimSpace(fileBaseName) == "" {
			return UninstallCAResult{}, fmt.Errorf("fileBaseName 不能为空（deleteLocal=true）")
		}
		certPath = filepath.Join(dir, fileBaseName+".crt")
		keyPath = filepath.Join(dir, fileBaseName+".key")
		_ = remove(certPath)
		_ = remove(keyPath)
	}

	return UninstallCAResult{
		Deleted:  deleted,
		CertPath: certPath,
		KeyPath:  keyPath,
	}, nil
}
