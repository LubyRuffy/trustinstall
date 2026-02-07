package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Installer interface {
	InstallCA(dir, fileBaseName, commonName string, deleteSame bool) error
}

type InstallCAResult struct {
	Dir          string
	FileBaseName string
	CommonName   string
	CertPath     string
	KeyPath      string
	Attempts     int
}

func expandDir(dir string) (string, error) {
	s := strings.TrimSpace(dir)
	if s == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("获取用户目录失败: %w", err)
		}
		return filepath.Join(home, ".trustinstall"), nil
	}

	if s == "~" || strings.HasPrefix(s, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("获取用户目录失败: %w", err)
		}
		if s == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(s, "~/")), nil
	}

	return s, nil
}

func RunInstallCA(inst Installer, opts InstallCAOptions) (InstallCAResult, error) {
	if inst == nil {
		return InstallCAResult{}, fmt.Errorf("installer 不能为空")
	}

	dir, err := expandDir(opts.Dir)
	if err != nil {
		return InstallCAResult{}, err
	}

	fileBaseName := strings.TrimSpace(opts.FileBaseName)
	if fileBaseName == "" {
		fileBaseName = "trustinstall-ca"
	}
	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		commonName = "trustinstall-ca"
	}

	attempts := 1
	if err := inst.InstallCA(dir, fileBaseName, commonName, opts.DeleteSame); err != nil {
		return InstallCAResult{}, err
	}

	return InstallCAResult{
		Dir:          dir,
		FileBaseName: fileBaseName,
		CommonName:   commonName,
		CertPath:     filepath.Join(dir, fileBaseName+".crt"),
		KeyPath:      filepath.Join(dir, fileBaseName+".key"),
		Attempts:     attempts,
	}, nil
}
