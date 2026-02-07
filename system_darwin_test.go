//go:build darwin

package trustinstall

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestParseSecurityFindCertificateOutput(t *testing.T) {
	now := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC)
	c1, _, pem1, _, err := generateSelfSignedCA("cn-1", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA #1 err=%v", err)
	}
	c2, _, pem2, _, err := generateSelfSignedCA("cn-2", now, rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCA #2 err=%v", err)
	}

	out := []byte("SHA-1 hash: AAAA\n" + string(pem1) + "SHA-1 hash: BBBB\n" + string(pem2))
	certs, err := parseSecurityFindCertificateOutput(out)
	if err != nil {
		t.Fatalf("parseSecurityFindCertificateOutput err=%v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
	if certs[0].SHA1 != "AAAA" || certs[1].SHA1 != "BBBB" {
		t.Fatalf("unexpected sha1 values: %+v", certs)
	}
	if certs[0].Cert.Subject.CommonName != c1.Subject.CommonName {
		t.Fatalf("unexpected CN1=%q", certs[0].Cert.Subject.CommonName)
	}
	if certs[1].Cert.Subject.CommonName != c2.Subject.CommonName {
		t.Fatalf("unexpected CN2=%q", certs[1].Cert.Subject.CommonName)
	}
}

func TestIsTrustedInAdminTrustSettings(t *testing.T) {
	root := map[string]interface{}{
		"trustList": map[string]interface{}{
			"ABC": map[string]interface{}{
				"trustSettings": []interface{}{
					map[string]interface{}{
						"kSecTrustSettingsPolicyName": "sslServer",
						"kSecTrustSettingsResult":     uint64(1),
					},
					map[string]interface{}{
						"kSecTrustSettingsPolicyName": "basicX509",
						"kSecTrustSettingsResult":     uint64(1),
					},
				},
			},
		},
	}

	if !isTrustedInAdminTrustSettings(root, "ABC") {
		t.Fatalf("expected trusted")
	}
	if isTrustedInAdminTrustSettings(root, "DEF") {
		t.Fatalf("expected not trusted")
	}
}
