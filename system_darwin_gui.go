//go:build darwin

package trustinstall

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/smallstep/truststore"
)

// darwinGUISystem 在 GUI 场景下避免直接在当前进程里执行 `sudo ...`，因为此时往往没有可交互 TTY。
// 策略：生成一个 `.command` 脚本并通过 `open` 弹出新的 Terminal 窗口运行，让用户在 Terminal 中输入密码。
// 然后在当前进程里轮询系统钥匙串/信任设置，等待变更生效。
type darwinGUISystem struct {
	*darwinSystem

	openCmd func(name string, args ...string) *exec.Cmd
}

// EnsureUninstallCerts 在一个弹出的 Terminal 窗口里删除所有给定证书（按 SHA1 删除），避免多次弹窗。
func (s *darwinGUISystem) EnsureUninstallCerts(certs []*x509.Certificate) error {
	var sha1s []string
	var cn string
	for _, c := range certs {
		if c == nil {
			continue
		}
		if cn == "" {
			cn = c.Subject.CommonName
		}
		sha1 := sha1Hex(c)
		if sha1 == "" {
			continue
		}
		sha1s = append(sha1s, sha1)
	}
	if len(sha1s) == 0 {
		return nil
	}

	lines := []string{
		"#!/bin/zsh",
		"set -euo pipefail",
		`echo "[trustinstall] 删除系统证书..."`,
	}
	for _, sha1 := range sha1s {
		lines = append(lines, fmt.Sprintf("sudo /usr/bin/security delete-certificate -Z %s /Library/Keychains/System.keychain || true", shellQuote(sha1)))
	}
	lines = append(lines,
		`echo "[trustinstall] 完成。你可以关闭该窗口。"`,
		"read -r _",
	)

	if err := s.openTerminalScript(strings.Join(lines, "\n") + "\n"); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return s.waitUntil(ctx, 700*time.Millisecond, func() (bool, error) {
		sysCerts, err := s.FindCertificatesByCommonName(cn)
		if err != nil {
			return false, err
		}
		left := make(map[string]bool, len(sha1s))
		for _, sha1 := range sha1s {
			left[strings.ToUpper(sha1)] = true
		}
		for _, c := range sysCerts {
			if left[strings.ToUpper(strings.TrimSpace(c.SHA1))] {
				return false, nil
			}
		}
		return true, nil
	})
}

// EnsureInstalledAndTrusted 会在一个弹出的 Terminal 窗口内完成：
// 1)（可选）删除系统中不一致的同名证书
// 2) 安装证书到系统钥匙串
// 3) 写入“始终信任”设置
//
// 这样可以避免在 GUI 场景下因为多个 sudo 步骤而弹出多个终端窗口。
func (s *darwinGUISystem) EnsureInstalledAndTrusted(certFile string, cert *x509.Certificate, deleteCerts []*x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("证书为空")
	}

	plistData, err := s.darwinSystem.makeTrustSettingsImportPlist(cert)
	if err != nil {
		return err
	}
	plistTmp, err := os.CreateTemp("", "trust-settings-import-*.plist")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	plistPath := plistTmp.Name()
	_ = plistTmp.Close()
	// 留给用户查看执行输出；不立即删除临时 plist，方便排障。
	if err := os.WriteFile(plistPath, plistData, 0o600); err != nil {
		return fmt.Errorf("写入 trust settings 失败: %w", err)
	}

	lines := []string{
		"#!/bin/zsh",
		"set -euo pipefail",
		`echo "[trustinstall] 需要管理员权限。请在本窗口输入密码。"`,
	}
	if len(deleteCerts) > 0 {
		lines = append(lines, `echo "[trustinstall] 删除系统中不一致的同名证书..."`)
		for _, dc := range deleteCerts {
			if dc == nil {
				continue
			}
			sha1 := sha1Hex(dc)
			if sha1 == "" {
				continue
			}
			lines = append(lines, fmt.Sprintf("sudo /usr/bin/security delete-certificate -Z %s /Library/Keychains/System.keychain || true", shellQuote(sha1)))
		}
	}

	lines = append(lines,
		`echo "[trustinstall] 安装证书并写入信任设置..."`,
		fmt.Sprintf("sudo /usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s || echo \"[trustinstall] add-trusted-cert 失败（可能已存在），继续...\"", shellQuote(certFile)),
		fmt.Sprintf("sudo /usr/bin/security trust-settings-import -d %s", shellQuote(plistPath)),
		`echo "[trustinstall] 完成。你可以关闭该窗口。"`,
		"read -r _",
	)

	script := strings.Join(lines, "\n") + "\n"
	if err := s.openTerminalScript(script); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return s.waitUntil(ctx, 700*time.Millisecond, func() (bool, error) {
		sysCerts, err := s.FindCertificatesByCommonName(cert.Subject.CommonName)
		if err != nil {
			return false, err
		}
		want := sha1Hex(cert)
		found := false
		for _, c := range sysCerts {
			if strings.EqualFold(strings.TrimSpace(c.SHA1), want) {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
		trusted, err := s.IsCertTrusted(cert)
		if err != nil {
			return false, err
		}
		return trusted, nil
	})
}

func (s *darwinGUISystem) InstallCertFile(certFile string) error {
	b, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	cert, err := parseCertificatePEM(b)
	if err != nil {
		return err
	}

	plistData, err := s.darwinSystem.makeTrustSettingsImportPlist(cert)
	if err != nil {
		return err
	}
	plistTmp, err := os.CreateTemp("", "trust-settings-import-*.plist")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	plistPath := plistTmp.Name()
	_ = plistTmp.Close()
	// 留给用户查看执行输出；不立即删除临时 plist，方便排障。
	if err := os.WriteFile(plistPath, plistData, 0o600); err != nil {
		return fmt.Errorf("写入 trust settings 失败: %w", err)
	}

	script := strings.Join([]string{
		"#!/bin/zsh",
		"set -euo pipefail",
		`echo "[trustinstall] 安装证书并写入信任设置..."`,
		fmt.Sprintf("sudo /usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s", shellQuote(certFile)),
		fmt.Sprintf("sudo /usr/bin/security trust-settings-import -d %s", shellQuote(plistPath)),
		`echo "[trustinstall] 完成。你可以关闭该窗口。"`,
		"read -r _",
	}, "\n") + "\n"

	if err := s.openTerminalScript(script); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	return s.waitUntil(ctx, 700*time.Millisecond, func() (bool, error) {
		sysCerts, err := s.FindCertificatesByCommonName(cert.Subject.CommonName)
		if err != nil {
			return false, err
		}
		want := sha1Hex(cert)
		for _, c := range sysCerts {
			if strings.EqualFold(strings.TrimSpace(c.SHA1), want) {
				trusted, err := s.IsCertTrusted(cert)
				if err != nil {
					return false, err
				}
				return trusted, nil
			}
		}
		return false, nil
	})
}

func (s *darwinGUISystem) TrustCert(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("证书为空")
	}

	// 复用 darwinSystem 里生成 trust-settings-import plist 的逻辑，但执行命令改为在 Terminal 中 sudo。
	plistRoot, err := s.readAdminTrustSettings()
	if err != nil {
		return err
	}
	if tv, ok := plistRoot["trustVersion"]; ok {
		switch x := tv.(type) {
		case uint64:
			if x != 1 {
				return fmt.Errorf("不支持的 trust settings 版本: %v", x)
			}
		case int64:
			if x != 1 {
				return fmt.Errorf("不支持的 trust settings 版本: %v", x)
			}
		}
	}

	trustList, ok := plistRoot["trustList"].(map[string]interface{})
	if !ok || trustList == nil {
		trustList = make(map[string]interface{})
		plistRoot["trustList"] = trustList
	}

	key := sha1Hex(cert)
	entry, _ := trustList[key].(map[string]interface{})
	if entry == nil {
		entry = make(map[string]interface{})
	}

	issuerNameASN1, err := marshalIssuerName(cert)
	if err == nil {
		entry["issuerName"] = issuerNameASN1
	}
	entry["serialNumber"] = cert.SerialNumber.Bytes()
	entry["modDate"] = time.Now()
	entry["trustSettings"] = darwinTrustSettings
	trustList[key] = entry

	plistData, err := marshalTrustSettings(plistRoot)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp("", "trust-settings-import-*.plist")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpName)

	if err := os.WriteFile(tmpName, plistData, 0o600); err != nil {
		return fmt.Errorf("写入 trust settings 失败: %w", err)
	}

	script := strings.Join([]string{
		"#!/bin/zsh",
		"set -euo pipefail",
		`echo "[trustinstall] 写入系统信任设置..."`,
		fmt.Sprintf("sudo /usr/bin/security trust-settings-import -d %s", shellQuote(tmpName)),
		`echo "[trustinstall] 完成。你可以关闭该窗口。"`,
		"read -r _",
	}, "\n") + "\n"

	if err := s.openTerminalScript(script); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return s.waitUntil(ctx, 700*time.Millisecond, func() (bool, error) {
		trusted, err := s.IsCertTrusted(cert)
		if err != nil {
			return false, err
		}
		return trusted, nil
	})
}

func (s *darwinGUISystem) UninstallCert(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("证书为空")
	}

	sha1 := sha1Hex(cert)
	if sha1 == "" {
		return fmt.Errorf("证书 SHA1 为空")
	}

	script := strings.Join([]string{
		"#!/bin/zsh",
		"set -euo pipefail",
		`echo "[trustinstall] 删除系统证书..."`,
		fmt.Sprintf("sudo /usr/bin/security delete-certificate -Z %s /Library/Keychains/System.keychain || true", shellQuote(sha1)),
		`echo "[trustinstall] 完成。你可以关闭该窗口。"`,
		"read -r _",
	}, "\n") + "\n"

	if err := s.openTerminalScript(script); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return s.waitUntil(ctx, 700*time.Millisecond, func() (bool, error) {
		sysCerts, err := s.FindCertificatesByCommonName(cert.Subject.CommonName)
		if err != nil {
			// 若 find-certificate 因权限/其他原因失败，返回错误让上层感知。
			return false, err
		}
		for _, c := range sysCerts {
			if strings.EqualFold(strings.TrimSpace(c.SHA1), sha1) {
				return false, nil
			}
		}
		return true, nil
	})
}

func (s *darwinGUISystem) openTerminalScript(script string) error {
	tmpDir, err := os.MkdirTemp("", "trustinstall-terminal-*")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}

	// 留给用户查看执行输出；不立即删除临时文件夹，避免调试困难。
	scriptPath := filepath.Join(tmpDir, "trustinstall.command")
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		return fmt.Errorf("写入脚本失败: %w", err)
	}

	cmd := s.openCmd("open", scriptPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return truststore.NewCmdError(err, cmd, out)
	}
	return nil
}

func (s *darwinGUISystem) waitUntil(ctx context.Context, interval time.Duration, cond func() (bool, error)) error {
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		ok, err := cond()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("等待系统变更超时（可能用户未在新 Terminal 中完成授权/输入密码）")
		case <-t.C:
		}
	}
}

func shellQuote(s string) string {
	// POSIX-ish single-quote escaping: ' -> '\'' .
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Below helpers keep darwinSystem.TrustCert logic reusable without exporting internals.

func marshalIssuerName(cert *x509.Certificate) ([]byte, error) {
	return issuerNameASN1(cert)
}

func marshalTrustSettings(plistRoot map[string]interface{}) ([]byte, error) {
	return trustSettingsPlist(plistRoot)
}
