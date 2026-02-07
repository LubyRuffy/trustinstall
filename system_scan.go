package trustinstall

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/smallstep/truststore"
)

// scanCertificatesByCommonName scans the given directories for certificate files and returns those
// whose Subject.CommonName equals commonName (case-insensitive).
//
// This is a best-effort helper used by non-macOS implementations; unreadable/invalid cert files are skipped.
func scanCertificatesByCommonName(dirs []string, commonName string) ([]systemCert, error) {
	cn := strings.TrimSpace(commonName)
	if cn == "" {
		return nil, fmt.Errorf("commonName 不能为空")
	}

	seen := make(map[string]bool)
	var out []systemCert

	for _, dir := range dirs {
		root := strings.TrimSpace(dir)
		if root == "" {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d == nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(d.Name()))
			if ext != ".crt" && ext != ".pem" && ext != ".cer" && ext != ".der" {
				return nil
			}

			cert, err := truststore.ReadCertificate(path)
			if err != nil || cert == nil {
				return nil
			}
			if !strings.EqualFold(strings.TrimSpace(cert.Subject.CommonName), cn) {
				return nil
			}

			sha1 := sha1Hex(cert)
			if sha1 == "" || seen[sha1] {
				return nil
			}
			seen[sha1] = true
			out = append(out, systemCert{SHA1: sha1, Cert: cert})
			return nil
		})
	}

	return out, nil
}
