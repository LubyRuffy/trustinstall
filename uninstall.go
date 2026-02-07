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

	type target struct {
		id   string
		cert *x509.Certificate
	}
	var targets []target
	for _, c := range certs {
		if c.Cert == nil {
			continue
		}
		id := strings.ToUpper(strings.TrimSpace(c.SHA1))
		if id == "" {
			id = strings.ToUpper(sha1Hex(c.Cert))
		}
		targets = append(targets, target{id: id, cert: c.Cert})
	}
	if len(targets) == 0 {
		return 0, nil
	}

	before := make(map[string]bool, len(targets))
	for _, t := range targets {
		if t.id != "" {
			before[t.id] = true
		}
	}

	if bat, ok := sys.(interface {
		EnsureUninstallCerts(certs []*x509.Certificate) error
	}); ok {
		var ts []*x509.Certificate
		for _, t := range targets {
			ts = append(ts, t.cert)
		}
		if err := bat.EnsureUninstallCerts(ts); err != nil {
			return 0, err
		}
	} else {
		for _, t := range targets {
			if err := sys.UninstallCert(t.cert); err != nil {
				return 0, wrapCmdError("删除系统证书失败", err)
			}
		}
	}

	afterCerts, err := sys.FindCertificatesByCommonName(cn)
	if err != nil {
		// 删除已执行，但无法重新查询，保守返回“尝试删除的数量”。
		return len(before), nil
	}
	after := make(map[string]bool, len(afterCerts))
	for _, c := range afterCerts {
		if c.Cert == nil {
			continue
		}
		id := strings.ToUpper(strings.TrimSpace(c.SHA1))
		if id == "" {
			id = strings.ToUpper(sha1Hex(c.Cert))
		}
		if id != "" {
			after[id] = true
		}
	}

	deleted := 0
	for id := range before {
		if !after[id] {
			deleted++
		}
	}
	return deleted, nil
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
