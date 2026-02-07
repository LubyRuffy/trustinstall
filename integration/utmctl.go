//go:build integration

package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const defaultUTMCtl = "/Applications/UTM.app/Contents/MacOS/utmctl"

func utmctlPath() string {
	if p := strings.TrimSpace(os.Getenv("TRUSTINSTALL_UTMCTL")); p != "" {
		return p
	}
	return defaultUTMCtl
}

func discoverUTMIPv4(identifier string) (string, error) {
	id := strings.TrimSpace(identifier)
	if id == "" {
		id = strings.TrimSpace(os.Getenv("TRUSTINSTALL_UTM_WINDOWS_VM"))
	}
	if id == "" {
		id = strings.TrimSpace(os.Getenv("TRUSTINSTALL_UTM_VM"))
	}
	if id == "" {
		// Last resort: if only one VM is registered, use it.
		ids, _ := utmctlList()
		if len(ids) == 1 {
			id = ids[0]
		}
	}
	if id == "" {
		return "", fmt.Errorf("未提供 UTM VM 标识：请设置 TRUSTINSTALL_UTM_WINDOWS_VM（或 TRUSTINSTALL_UTM_VM）为 VM 完整名称或 UUID")
	}

	utmctl := utmctlPath()
	cmd := exec.Command(utmctl, "ip-address", "--hide", id)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("utmctl ip-address 失败: %w: %s", err, out.String())
	}

	lines := strings.Split(out.String(), "\n")
	for _, ln := range lines {
		s := strings.TrimSpace(ln)
		if s == "" {
			continue
		}
		// Prefer IPv4.
		if strings.Contains(s, ".") && !strings.Contains(s, ":") {
			return s, nil
		}
	}
	// If no IPv4, return first non-empty line.
	for _, ln := range lines {
		s := strings.TrimSpace(ln)
		if s != "" {
			return s, nil
		}
	}
	return "", fmt.Errorf("utmctl ip-address 未返回任何地址（identifier=%q）", id)
}

func utmctlList() ([]string, error) {
	utmctl := utmctlPath()
	cmd := exec.Command(utmctl, "list", "--hide")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	// Output format is not formally specified. We keep this best-effort:
	// take the last whitespace-separated token from each non-empty line as identifier.
	var ids []string
	for _, ln := range strings.Split(string(out), "\n") {
		s := strings.TrimSpace(ln)
		if s == "" {
			continue
		}
		parts := strings.Fields(s)
		if len(parts) == 0 {
			continue
		}
		ids = append(ids, parts[len(parts)-1])
	}
	return ids, nil
}
