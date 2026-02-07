//go:build integration

package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

const defaultUTMCtl = "/Applications/UTM.app/Contents/MacOS/utmctl"
const defaultCIPrefixOS = "ci-os"
const defaultCIPrefixCI = "ci-"

func utmctlPath() string {
	if p := strings.TrimSpace(os.Getenv("TRUSTINSTALL_UTMCTL")); p != "" {
		return p
	}
	return defaultUTMCtl
}

type utmVM struct {
	UUID string
	Name string
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
		// CI 默认：优先选择名称前缀为 ci-os 的 VM。
		vms, _ := utmctlListVMs()
		id = pickUTMVMIdentifier(vms)
	}
	// If utmctl list is unavailable (e.g. SSH session / no login), fall back to scanning.
	if id == "" {
		if ip, err := discoverWindowsVMIPv4ByScan(5985); err == nil {
			return ip, nil
		}
		return "", fmt.Errorf("未提供 UTM VM 标识：请设置 TRUSTINSTALL_UTM_WINDOWS_VM（或 TRUSTINSTALL_UTM_VM）为 VM 完整名称或 UUID；或确保存在一个以 %q 或 %q 开头的 Windows VM（例如 ci-Windows）；若在无登录/SSH 场景 utmctl 不可用，可设置 TRUSTINSTALL_WINDOWS_DISCOVERY_CIDRS 或手动设置 TRUSTINSTALL_WINDOWS_WINRM_ENDPOINT", defaultCIPrefixOS, defaultCIPrefixCI)
	}

	utmctl := utmctlPath()
	cmd := exec.Command(utmctl, "ip-address", "--hide", id)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		// If utmctl cannot talk to the UI session, fall back to scanning.
		if ip, scanErr := discoverWindowsVMIPv4ByScan(5985); scanErr == nil {
			return ip, nil
		}
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

func pickUTMVMIdentifier(vms []utmVM) string {
	if len(vms) == 0 {
		return ""
	}

	var ci []utmVM
	for _, vm := range vms {
		name := strings.ToLower(strings.TrimSpace(vm.Name))
		if strings.HasPrefix(name, defaultCIPrefixOS) || strings.HasPrefix(name, defaultCIPrefixCI) {
			ci = append(ci, vm)
		}
	}

	// Prefer Windows VM in CI by name.
	for _, vm := range ci {
		name := strings.ToLower(strings.TrimSpace(vm.Name))
		if strings.Contains(name, "windows") || strings.Contains(name, "win") {
			return vm.Name
		}
	}
	if len(ci) == 1 {
		// Use name to avoid UUID formatting issues.
		return ci[0].Name
	}
	if len(ci) > 1 {
		// Deterministic pick: smallest name.
		sort.Slice(ci, func(i, j int) bool { return ci[i].Name < ci[j].Name })
		return ci[0].Name
	}

	if len(vms) == 1 {
		return vms[0].Name
	}
	return ""
}

func utmctlListVMs() ([]utmVM, error) {
	utmctl := utmctlPath()
	cmd := exec.Command(utmctl, "list", "--hide")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	// Example output:
	// UUID                                 Status   Name
	// 123e4567-e89b-12d3-a456-426614174000  Running  ci-os-windows
	re := regexp.MustCompile(`^([0-9a-fA-F-]{36})\s+\S+\s+(.+)$`)
	var vms []utmVM
	for _, ln := range strings.Split(string(out), "\n") {
		s := strings.TrimSpace(ln)
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "UUID") && strings.Contains(s, "Status") {
			continue
		}
		m := re.FindStringSubmatch(s)
		if len(m) != 3 {
			continue
		}
		vms = append(vms, utmVM{UUID: strings.TrimSpace(m[1]), Name: strings.TrimSpace(m[2])})
	}
	return vms, nil
}

func utmctlExec(identifier string, cmdArgs ...string) (string, error) {
	id := strings.TrimSpace(identifier)
	if id == "" {
		// Same selection logic as discoverUTMIPv4
		id = strings.TrimSpace(os.Getenv("TRUSTINSTALL_UTM_WINDOWS_VM"))
		if id == "" {
			vms, _ := utmctlListVMs()
			id = pickUTMVMIdentifier(vms)
		}
	}
	if id == "" {
		return "", fmt.Errorf("未提供 UTM VM 标识：请设置 TRUSTINSTALL_UTM_WINDOWS_VM")
	}
	utmctl := utmctlPath()

	args := []string{"exec", "--hide", id, "--cmd"}
	args = append(args, cmdArgs...)
	c := exec.Command(utmctl, args...)
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("utmctl exec 失败: %w: %s", err, string(out))
	}
	return string(out), nil
}
