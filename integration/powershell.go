//go:build integration || all_platform

package integration

import (
	"encoding/base64"
	"strings"
	"unicode/utf16"
)

func psSingleQuote(s string) string {
	// PowerShell single-quoted string escaping: '' represents a single '.
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func encodePowerShellEncodedCommand(script string) string {
	// PowerShell -EncodedCommand expects UTF-16LE base64.
	u16 := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(u16)*2)
	for _, v := range u16 {
		b = append(b, byte(v), byte(v>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}
