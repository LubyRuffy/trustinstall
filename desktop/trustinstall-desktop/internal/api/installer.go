package api

import (
	"github.com/LubyRuffy/trustinstall"
)

type trustinstallInstaller struct{}

func (trustinstallInstaller) InstallCA(dir, fileBaseName, commonName string, deleteSame bool) error {
	ti, err := trustinstall.New(trustinstall.Options{
		Dir:          dir,
		FileBaseName: fileBaseName,
		CommonName:   commonName,
		DeleteSame:   &deleteSame,
	})
	if err != nil {
		return err
	}
	return ti.InstallCA()
}

func (trustinstallInstaller) UninstallCA(dir, fileBaseName, commonName string, deleteLocal bool) (int, string, string, error) {
	ti, err := trustinstall.New(trustinstall.Options{
		Dir:          dir,
		FileBaseName: fileBaseName,
		CommonName:   commonName,
	})
	if err != nil {
		return 0, "", "", err
	}
	res, err := ti.UninstallCA(deleteLocal)
	if err != nil {
		return 0, "", "", err
	}
	return res.Deleted, res.CertPath, res.KeyPath, nil
}

func defaultInstaller() Manager {
	return trustinstallInstaller{}
}
