package trustinstall

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type windowsCertItem struct {
	Thumbprint string `json:"Thumbprint"`
	CommonName string `json:"CommonName"`
	RawBase64  string `json:"RawBase64"`
}

func parseWindowsCertItemsJSON(b []byte) ([]windowsCertItem, error) {
	var arr []windowsCertItem
	if err := json.Unmarshal(b, &arr); err == nil {
		return arr, nil
	}
	var one windowsCertItem
	if err := json.Unmarshal(b, &one); err == nil {
		return []windowsCertItem{one}, nil
	}
	return nil, fmt.Errorf("解析 Windows 证书列表 JSON 失败")
}

func normalizeThumbprint(s string) string {
	x := strings.ToUpper(strings.TrimSpace(s))
	x = strings.ReplaceAll(x, " ", "")
	return x
}

func decodeWindowsRawCert(rawBase64 string) ([]byte, error) {
	if strings.TrimSpace(rawBase64) == "" {
		return nil, fmt.Errorf("RawBase64 为空")
	}
	return base64.StdEncoding.DecodeString(rawBase64)
}
