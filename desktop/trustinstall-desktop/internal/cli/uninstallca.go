package cli

import (
	"fmt"
	"strings"
)

type Uninstaller interface {
	UninstallCA(dir, fileBaseName, commonName string, deleteLocal bool) (deleted int, certPath, keyPath string, err error)
}

type UninstallCAResult struct {
	CommonName string
	Deleted    int
	CertPath   string
	KeyPath    string
}

func RunUninstallCA(u Uninstaller, opts UninstallCAOptions) (UninstallCAResult, error) {
	if u == nil {
		return UninstallCAResult{}, fmt.Errorf("uninstaller 不能为空")
	}

	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		commonName = "trustinstall-ca"
	}

	dir, err := expandDir(opts.Dir)
	if err != nil {
		return UninstallCAResult{}, err
	}
	fileBaseName := strings.TrimSpace(opts.FileBaseName)
	if fileBaseName == "" {
		fileBaseName = "trustinstall-ca"
	}

	deleted, certPath, keyPath, err := u.UninstallCA(dir, fileBaseName, commonName, opts.DeleteLocal)
	if err != nil {
		return UninstallCAResult{}, err
	}

	return UninstallCAResult{
		CommonName: commonName,
		Deleted:    deleted,
		CertPath:   certPath,
		KeyPath:    keyPath,
	}, nil
}
