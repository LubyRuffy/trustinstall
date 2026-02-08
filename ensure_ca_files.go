package trustinstall

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// EnsureCAFiles 生成或复用 dir 下的自签名根证书（CA），仅负责写入/校验本地文件，不触发系统安装或信任设置。
//
// 文件会写入：
//   - <dir>/<fileBaseName>.crt (PEM)
//   - <dir>/<fileBaseName>.key (PEM, PKCS#8)
//
// 若文件已存在，会校验证书为 CA 且与私钥匹配。
// 返回值为 certPath/keyPath 以及解析后的 CA 证书。
func EnsureCAFiles(dir, fileBaseName, commonName string) (certPath, keyPath string, cert *x509.Certificate, err error) {
	return ensureCAFiles(dir, fileBaseName, commonName, time.Now, rand.Reader)
}

func ensureCAFiles(dir, fileBaseName, commonName string, now func() time.Time, randReader io.Reader) (certPath, keyPath string, cert *x509.Certificate, err error) {
	if err := validateInputs(dir, fileBaseName, commonName); err != nil {
		return "", "", nil, err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", nil, fmt.Errorf("创建目录失败: %w", err)
	}

	certFile, keyFile := caPaths(dir, fileBaseName)
	cert, _, err = loadCA(certFile, keyFile)
	switch {
	case err == nil:
		return certFile, keyFile, cert, nil
	case errors.Is(err, os.ErrNotExist):
		var certPEM, keyPEM []byte
		cert, _, certPEM, keyPEM, err = generateSelfSignedCA(commonName, now(), randReader)
		if err != nil {
			return "", "", nil, err
		}
		if err := writeCA(certFile, keyFile, certPEM, keyPEM); err != nil {
			return "", "", nil, err
		}

		return certFile, keyFile, cert, nil
	default:
		return "", "", nil, err
	}
}
