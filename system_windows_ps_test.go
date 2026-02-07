package trustinstall

import (
	"encoding/base64"
	"testing"
)

func TestParseWindowsCertItemsJSON_ArrayAndSingle(t *testing.T) {
	t.Parallel()

	raw := []byte{1, 2, 3}
	b64 := base64.StdEncoding.EncodeToString(raw)

	// array
	items, err := parseWindowsCertItemsJSON([]byte(`[{"Thumbprint":"aa bb","CommonName":"cn","RawBase64":"` + b64 + `"}]`))
	if err != nil {
		t.Fatalf("parse array err=%v", err)
	}
	if len(items) != 1 || items[0].CommonName != "cn" {
		t.Fatalf("items=%v", items)
	}
	if normalizeThumbprint(items[0].Thumbprint) != "AABB" {
		t.Fatalf("thumb=%q", normalizeThumbprint(items[0].Thumbprint))
	}
	dec, err := decodeWindowsRawCert(items[0].RawBase64)
	if err != nil {
		t.Fatalf("decode err=%v", err)
	}
	if len(dec) != 3 || dec[0] != 1 {
		t.Fatalf("dec=%v", dec)
	}

	// single
	items2, err := parseWindowsCertItemsJSON([]byte(`{"Thumbprint":"CC","CommonName":"cn","RawBase64":"` + b64 + `"}`))
	if err != nil {
		t.Fatalf("parse single err=%v", err)
	}
	if len(items2) != 1 || items2[0].Thumbprint != "CC" {
		t.Fatalf("items2=%v", items2)
	}
}
