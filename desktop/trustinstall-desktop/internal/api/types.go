package api

type Manager interface {
	InstallCA(dir, fileBaseName, commonName string, deleteSame bool) error
	UninstallCA(dir, fileBaseName, commonName string, deleteLocal bool) (deleted int, certPath, keyPath string, err error)
}
