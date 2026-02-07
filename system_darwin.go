//go:build darwin

package trustinstall

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/smallstep/truststore"
	"golang.org/x/term"
	plist "howett.net/plist"
)

type darwinSystem struct {
	execCmd func(name string, args ...string) *exec.Cmd
}

func newSystemOps() (systemOps, error) {
	ds := &darwinSystem{execCmd: exec.Command}

	// 在 GUI / 无交互 TTY 场景下（例如 Wails dev、LaunchServices 启动等），直接执行 `sudo security ...`
	// 往往会卡在 Password: 或被系统拒绝交互。此时自动切换为“弹出新 Terminal”的实现。
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return &darwinGUISystem{
			darwinSystem: ds,
			openCmd:      exec.Command,
		}, nil
	}

	return ds, nil
}

func (s *darwinSystem) FindCertificatesByCommonName(commonName string) ([]systemCert, error) {
	cmd := s.execCmd("security", "find-certificate", "-a", "-c", commonName, "-Z", "-p", "/Library/Keychains/System.keychain")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, truststore.NewCmdError(err, cmd, out)
	}
	return parseSecurityFindCertificateOutput(out)
}

func parseSecurityFindCertificateOutput(out []byte) ([]systemCert, error) {
	var res []systemCert

	var sha1Line string
	var pemBuf bytes.Buffer
	inPEM := false

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "SHA-1 hash: ") {
			sha1Line = strings.TrimSpace(strings.TrimPrefix(line, "SHA-1 hash: "))
			continue
		}

		if line == "-----BEGIN CERTIFICATE-----" {
			inPEM = true
			pemBuf.Reset()
			_, _ = pemBuf.WriteString(line)
			_, _ = pemBuf.WriteString("\n")
			continue
		}

		if !inPEM {
			continue
		}

		_, _ = pemBuf.WriteString(line)
		_, _ = pemBuf.WriteString("\n")
		if line != "-----END CERTIFICATE-----" {
			continue
		}

		inPEM = false
		block, _ := pem.Decode(pemBuf.Bytes())
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析系统证书失败: %w", err)
		}
		res = append(res, systemCert{
			SHA1: sha1Line,
			Cert: cert,
		})
		sha1Line = ""
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取系统证书输出失败: %w", err)
	}
	return res, nil
}

func (s *darwinSystem) IsCertTrusted(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, fmt.Errorf("证书为空")
	}
	root, err := s.readAdminTrustSettings()
	if err != nil {
		return false, err
	}
	return isTrustedInAdminTrustSettings(root, sha1Hex(cert)), nil
}

func isTrustedInAdminTrustSettings(plistRoot map[string]interface{}, sha1HexUpper string) bool {
	trustList, ok := plistRoot["trustList"].(map[string]interface{})
	if !ok || trustList == nil {
		return false
	}

	entry, ok := trustList[sha1HexUpper].(map[string]interface{})
	if !ok || entry == nil {
		return false
	}

	settings, ok := entry["trustSettings"].([]interface{})
	if !ok || len(settings) == 0 {
		return false
	}

	hasSSL := false
	hasBasic := false
	for _, item := range settings {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := m["kSecTrustSettingsPolicyName"].(string)
		if !trustSettingResultIsAlwaysTrust(m["kSecTrustSettingsResult"]) {
			continue
		}
		switch name {
		case "sslServer":
			hasSSL = true
		case "basicX509":
			hasBasic = true
		}
	}

	return hasSSL && hasBasic
}

func trustSettingResultIsAlwaysTrust(v interface{}) bool {
	switch x := v.(type) {
	case uint64:
		return x == 1
	case int64:
		return x == 1
	case int:
		return x == 1
	default:
		return false
	}
}

func (s *darwinSystem) InstallCertFile(certFile string) error {
	return truststore.InstallFile(certFile)
}

func (s *darwinSystem) TrustCert(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("证书为空")
	}
	plistData, err := s.makeTrustSettingsImportPlist(cert)
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

	cmd := s.execCmd("sudo", "security", "trust-settings-import", "-d", tmpName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return truststore.NewCmdError(err, cmd, out)
	}
	return nil
}

func (s *darwinSystem) makeTrustSettingsImportPlist(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("证书为空")
	}

	plistRoot, err := s.readAdminTrustSettings()
	if err != nil {
		return nil, err
	}
	if tv, ok := plistRoot["trustVersion"]; ok {
		switch x := tv.(type) {
		case uint64:
			if x != 1 {
				return nil, fmt.Errorf("不支持的 trust settings 版本: %v", x)
			}
		case int64:
			if x != 1 {
				return nil, fmt.Errorf("不支持的 trust settings 版本: %v", x)
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

	issuerNameASN1, err := issuerNameASN1(cert)
	if err == nil {
		entry["issuerName"] = issuerNameASN1
	}
	entry["serialNumber"] = cert.SerialNumber.Bytes()
	entry["modDate"] = time.Now()
	entry["trustSettings"] = darwinTrustSettings
	trustList[key] = entry

	plistData, err := trustSettingsPlist(plistRoot)
	if err != nil {
		return nil, fmt.Errorf("序列化 trust settings 失败: %w", err)
	}
	return plistData, nil
}

func (s *darwinSystem) UninstallCert(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("证书为空")
	}

	cn := strings.TrimSpace(cert.Subject.CommonName)
	want := strings.ToUpper(strings.TrimSpace(sha1Hex(cert)))
	if want == "" {
		return fmt.Errorf("证书 SHA1 为空")
	}

	// 某些情况下 System.keychain 里可能存在重复项（甚至相同 SHA1 的多份），`security delete-certificate`
	// 可能需要多次调用才能删干净。这里做一个“删到查不到为止”的小循环，避免用户需要重复执行卸载命令。
	for i := 0; i < 6; i++ {
		_ = truststore.Uninstall(cert) // ignore error; fallback below handles the heavy lifting

		cmd := s.execCmd("sudo", "security", "delete-certificate", "-Z", want, "/Library/Keychains/System.keychain")
		out, err := cmd.CombinedOutput()
		if err != nil {
			// 如果本来就不存在，也视为成功。
			if bytes.Contains(bytes.ToLower(out), []byte("could not be found")) ||
				bytes.Contains(bytes.ToLower(out), []byte("not be found")) {
				return nil
			}
			return truststore.NewCmdError(err, cmd, out)
		}

		// verify
		if cn != "" {
			sysCerts, err := s.FindCertificatesByCommonName(cn)
			if err == nil {
				still := false
				for _, c := range sysCerts {
					if strings.EqualFold(strings.TrimSpace(c.SHA1), want) {
						still = true
						break
					}
				}
				if !still {
					return nil
				}
			}
		}

		time.Sleep(150 * time.Millisecond)
	}

	return fmt.Errorf("删除系统证书失败：重试多次后仍能查询到该证书（CN=%q, SHA1=%s）", cn, want)
}

func (s *darwinSystem) readAdminTrustSettings() (map[string]interface{}, error) {
	tmp, err := os.CreateTemp("", "trust-settings-export-*.plist")
	if err != nil {
		return nil, fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpName)

	cmd := s.execCmd("security", "trust-settings-export", "-d", tmpName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, truststore.NewCmdError(err, cmd, out)
	}

	b, err := os.ReadFile(tmpName)
	if err != nil {
		return nil, fmt.Errorf("读取 trust settings 失败: %w", err)
	}

	var plistRoot map[string]interface{}
	if _, err := plist.Unmarshal(b, &plistRoot); err != nil {
		return nil, fmt.Errorf("解析 trust settings 失败: %w", err)
	}
	return plistRoot, nil
}

func issuerNameASN1(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("证书为空")
	}
	return asn1.Marshal(cert.Subject.ToRDNSequence())
}

func trustSettingsPlist(plistRoot map[string]interface{}) ([]byte, error) {
	return plist.MarshalIndent(plistRoot, plist.XMLFormat, "\t")
}

// Trust settings for Always Trust (SSL + basic).
// Copied from github.com/smallstep/truststore.
var darwinTrustSettings []interface{}
var _, _ = plist.Unmarshal(darwinTrustSettingsData, &darwinTrustSettings)
var darwinTrustSettingsData = []byte(`
<array>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAED
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>sslServer</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAEC
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>basicX509</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
</array>
`)
