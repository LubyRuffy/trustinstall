package trustinstall

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/smallstep/truststore"
)

type systemCert struct {
	SHA1 string
	Cert *x509.Certificate
}

type systemOps interface {
	FindCertificatesByCommonName(commonName string) ([]systemCert, error)
	IsCertTrusted(cert *x509.Certificate) (bool, error)
	InstallCertFile(certFile string) error
	TrustCert(cert *x509.Certificate) error
	UninstallCert(cert *x509.Certificate) error
}

type installDeps struct {
	now        func() time.Time
	randReader io.Reader
	sys        systemOps
}

// InstallCA 生成或复用 dir 下的自签名根证书（CA），并确保其已安装到系统证书且设置为始终可信。
//
// 文件会写入：
//   - <dir>/<fileBaseName>.crt (PEM)
//   - <dir>/<fileBaseName>.key (PEM, PKCS#8)
//
// commonName 用于生成 CA 的证书 CommonName。若证书文件已存在则以文件内证书为准。
//
// deleteSame 表示当系统中存在多个同名（CommonName 相同）证书时，是否删除与本地证书文件不一致的系统证书。
//
// 注意：在 macOS 上安装到系统钥匙串通常需要管理员权限（truststore 内部会调用 sudo security ...）。
func defaultRandReader() io.Reader { return rand.Reader }

func installCA(dir, fileBaseName, commonName string, deleteSame bool, d installDeps) error {
	if err := validateInputs(dir, fileBaseName, commonName); err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	certFile, keyFile := caPaths(dir, fileBaseName)
	cert, _, err := loadCA(certFile, keyFile)
	switch {
	case err == nil:
		// reuse existing
	case errors.Is(err, os.ErrNotExist):
		genCert, _, certPEM, keyPEM, genErr := generateSelfSignedCA(commonName, d.now(), d.randReader)
		if genErr != nil {
			return genErr
		}
		if writeErr := writeCA(certFile, keyFile, certPEM, keyPEM); writeErr != nil {
			return writeErr
		}

		cert = genCert
	default:
		return err
	}

	sysCerts, err := d.sys.FindCertificatesByCommonName(cert.Subject.CommonName)
	if err != nil {
		return fmt.Errorf("查询系统证书失败: %w", err)
	}

	wantSHA1 := sha1Hex(cert)
	installed := false
	var mismatched []*x509.Certificate
	for _, c := range sysCerts {
		if strings.EqualFold(strings.TrimSpace(c.SHA1), wantSHA1) {
			installed = true
			continue
		}
		if c.Cert != nil {
			mismatched = append(mismatched, c.Cert)
		}
	}

	trusted := false
	if installed {
		var err error
		trusted, err = d.sys.IsCertTrusted(cert)
		if err != nil {
			return fmt.Errorf("检查证书信任状态失败: %w", err)
		}
	}

	needDelete := deleteSame && len(mismatched) > 0
	needPriv := needDelete || !installed || (installed && !trusted)

	// GUI 场景下可能需要把“删除+安装+写入信任”合并到一次提权交互里，避免弹出多个终端窗口。
	if needPriv {
		if ei, ok := d.sys.(interface {
			EnsureInstalledAndTrusted(certFile string, cert *x509.Certificate, deleteCerts []*x509.Certificate) error
		}); ok {
			var dels []*x509.Certificate
			if needDelete {
				dels = mismatched
			}
			if err := ei.EnsureInstalledAndTrusted(certFile, cert, dels); err != nil {
				return err
			}
			return nil
		}
	}

	if needDelete {
		for _, mc := range mismatched {
			if err := d.sys.UninstallCert(mc); err != nil {
				return wrapCmdError("删除系统中不一致的同名证书失败", err)
			}
		}
	}

	if !installed {
		if err := d.sys.InstallCertFile(certFile); err != nil {
			return wrapCmdError("安装证书到系统信任存储失败", err)
		}
		installed = true
	}

	if installed && trusted {
		return nil
	}
	if err := d.sys.TrustCert(cert); err != nil {
		return wrapCmdError("设置证书为始终信任失败", err)
	}
	return nil
}

func wrapCmdError(msg string, err error) error {
	var cmdErr *truststore.CmdError
	if errors.As(err, &cmdErr) {
		if out := strings.TrimSpace(string(cmdErr.Out())); out != "" {
			return fmt.Errorf("%s: %s: %w", msg, out, err)
		}
	}
	return fmt.Errorf("%s: %w", msg, err)
}

func validateInputs(dir, fileBaseName, commonName string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("dir 不能为空")
	}
	if strings.TrimSpace(fileBaseName) == "" {
		return fmt.Errorf("file_base_name 不能为空")
	}
	if strings.TrimSpace(commonName) == "" {
		return fmt.Errorf("commonName 不能为空")
	}
	// Avoid path traversal and surprising output paths.
	if filepath.Base(fileBaseName) != fileBaseName {
		return fmt.Errorf("file_base_name 不能包含路径: %q", fileBaseName)
	}
	// Also reject common separators explicitly, even if they are not native on the current OS.
	if strings.ContainsAny(fileBaseName, `/\\`) {
		return fmt.Errorf("file_base_name 非法: %q", fileBaseName)
	}
	return nil
}

func caPaths(dir, fileBaseName string) (certFile, keyFile string) {
	return filepath.Join(dir, fileBaseName+".crt"), filepath.Join(dir, fileBaseName+".key")
}

func loadCA(certFile, keyFile string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}

	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("读取证书失败: %w", err)
	}
	if !cert.IsCA {
		return nil, nil, fmt.Errorf("证书不是 CA: %s", certFile)
	}

	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("读取私钥失败: %w", err)
	}
	if err := verifyKeyMatchesCert(key, cert); err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func parseCertificatePEM(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("无效的证书 PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKeyPEM(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("无效的私钥 PEM")
	}

	// We always write PKCS#8 ("PRIVATE KEY") but accept common formats.
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("不支持的私钥类型: %T", k)
		}
		return s, nil
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return k, nil
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return k, nil
	default:
		return nil, fmt.Errorf("不支持的私钥 PEM 类型: %q", block.Type)
	}
}

func verifyKeyMatchesCert(key crypto.Signer, cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("证书为空")
	}
	if key == nil {
		return fmt.Errorf("私钥为空")
	}
	if !publicKeysEqual(key.Public(), cert.PublicKey) {
		return fmt.Errorf("私钥与证书不匹配")
	}
	return nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	// x509 provides MarshalPKIXPublicKey for stable, comparable encoding.
	ab, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bb, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}

func generateSelfSignedCA(commonName string, now time.Time, randReader io.Reader) (*x509.Certificate, crypto.Signer, []byte, []byte, error) {
	if strings.TrimSpace(commonName) == "" {
		return nil, nil, nil, nil, fmt.Errorf("commonName 不能为空")
	}
	if randReader == nil {
		return nil, nil, nil, nil, fmt.Errorf("randReader 不能为空")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), randReader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("生成私钥失败: %w", err)
	}

	serial, err := randSerial(randReader)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Root CA template.
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(randReader, tpl, tpl, key.Public(), key)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("生成证书失败: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("解析证书失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("序列化私钥失败: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return cert, key, certPEM, keyPEM, nil
}

func randSerial(randReader io.Reader) (*big.Int, error) {
	// 128-bit serial number.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(randReader, limit)
	if err != nil {
		return nil, fmt.Errorf("生成序列号失败: %w", err)
	}
	return serial, nil
}

func writeCA(certFile, keyFile string, certPEM, keyPEM []byte) error {
	if err := writeFileAtomic(certFile, certPEM, 0o644); err != nil {
		return fmt.Errorf("写入证书文件失败: %w", err)
	}
	if err := writeFileAtomic(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("写入私钥文件失败: %w", err)
	}
	return nil
}

func writeFileAtomic(filename string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filename)
	tmp, err := os.CreateTemp(dir, filepath.Base(filename)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filename)
}

func sha1Hex(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
