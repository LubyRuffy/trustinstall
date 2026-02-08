//go:build integration || all_platform

package integration

import (
	"os"
	"strings"
)

func isFalseyEnv(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	return s == "0" || s == "false" || s == "no" || s == "off"
}

func isTruthyEnv(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	return s == "1" || s == "true" || s == "yes" || s == "on"
}

func isCIHostByName() bool {
	h, err := os.Hostname()
	if err != nil {
		return false
	}
	h = strings.ToLower(strings.TrimSpace(h))
	return strings.HasPrefix(h, "ci-") || strings.HasPrefix(h, "ci")
}
