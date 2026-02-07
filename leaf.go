package trustinstall

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// LeafCertificate 根据 InstallCA 生成的 CA 私钥，动态生成指定 host 的证书。
//
// 返回：
//   - certPEM：叶子证书 PEM + CA 证书 PEM（链）
//   - keyPEM：叶子证书私钥 PEM（PKCS#8）
func leafCertificate(dir, fileBaseName, host string) (certPEM, keyPEM []byte, err error) {
	if strings.TrimSpace(host) == "" {
		return nil, nil, fmt.Errorf("host 不能为空")
	}

	caCertFile, caKeyFile := caPaths(dir, fileBaseName)
	caCert, caKey, err := loadCA(caCertFile, caKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("读取 CA 失败: %w", err)
	}
	return generateLeafCertificate(host, caCert, caKey, time.Now(), rand.Reader)
}

func generateLeafCertificate(host string, caCert *x509.Certificate, caKey crypto.Signer, now time.Time, randReader io.Reader) ([]byte, []byte, error) {
	if strings.TrimSpace(host) == "" {
		return nil, nil, fmt.Errorf("host 不能为空")
	}
	if caCert == nil || caKey == nil {
		return nil, nil, fmt.Errorf("CA 证书或私钥为空")
	}
	if randReader == nil {
		return nil, nil, fmt.Errorf("randReader 不能为空")
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), randReader)
	if err != nil {
		return nil, nil, fmt.Errorf("生成叶子证书私钥失败: %w", err)
	}
	serial, err := randSerial(randReader)
	if err != nil {
		return nil, nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(randReader, tpl, caCert, leafKey.Public(), caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("生成叶子证书失败: %w", err)
	}

	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("解析叶子证书失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})
	certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化叶子证书私钥失败: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}
