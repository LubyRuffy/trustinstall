package trustinstall

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Options struct {
	// Dir is the directory holding CA files. Default: ~/.trustinstall
	Dir string
	// FileBaseName is the base filename (without extension). Default: trustinstall-ca
	FileBaseName string
	// CommonName is the CA certificate CommonName to generate with. Default: trustinstall-ca
	// If CA files already exist, CN is determined by the existing certificate.
	CommonName string
	// DeleteSame controls whether to delete mismatched system certs with same CommonName. Default: true
	DeleteSame *bool
}

type Client struct {
	dir          string
	fileBaseName string
	commonName   string
	deleteSame   bool

	newSys func() (systemOps, error)
	now    func() time.Time
}

func New(opts Options) (*Client, error) {
	dir, err := expandDirDefault(opts.Dir)
	if err != nil {
		return nil, err
	}
	fileBaseName := strings.TrimSpace(opts.FileBaseName)
	if fileBaseName == "" {
		fileBaseName = "trustinstall-ca"
	}
	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		commonName = "trustinstall-ca"
	}
	deleteSame := true
	if opts.DeleteSame != nil {
		deleteSame = *opts.DeleteSame
	}

	if err := validateInputs(dir, fileBaseName, commonName); err != nil {
		return nil, err
	}

	return &Client{
		dir:          dir,
		fileBaseName: fileBaseName,
		commonName:   commonName,
		deleteSame:   deleteSame,
		newSys:       newSystemOps,
		now:          time.Now,
	}, nil
}

func (c *Client) InstallCA() error {
	if c == nil {
		return fmt.Errorf("client 不能为空")
	}
	sys, err := c.newSys()
	if err != nil {
		return err
	}
	return installCA(c.dir, c.fileBaseName, c.commonName, c.deleteSame, installDeps{
		now:        c.now,
		randReader: defaultRandReader(),
		sys:        sys,
	})
}

func (c *Client) UninstallCA(deleteLocal bool) (UninstallCAResult, error) {
	if c == nil {
		return UninstallCAResult{}, fmt.Errorf("client 不能为空")
	}
	sys, err := c.newSys()
	if err != nil {
		return UninstallCAResult{}, err
	}
	return uninstallCAWithSys(c.dir, c.fileBaseName, c.commonName, deleteLocal, sys, os.Remove)
}

func (c *Client) LeafCertificate(host string) (certPEM, keyPEM []byte, err error) {
	if c == nil {
		return nil, nil, fmt.Errorf("client 不能为空")
	}
	return leafCertificate(c.dir, c.fileBaseName, host)
}

func (c *Client) Dir() string          { return c.dir }
func (c *Client) FileBaseName() string { return c.fileBaseName }
func (c *Client) CommonName() string   { return c.commonName }
func (c *Client) DeleteSame() bool     { return c.deleteSame }

func expandDirDefault(dir string) (string, error) {
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
