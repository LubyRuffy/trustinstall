//go:build integration

package integration

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const defaultUTMCtl = "/Applications/UTM.app/Contents/MacOS/utmctl"
const defaultCIPrefixOS = "ci-os"
const defaultCIPrefixCI = "ci-"

// utmDebugf is a test-only debug hook; keep it nil in normal runs.
var utmDebugf func(format string, args ...any)

func utmLogf(format string, args ...any) {
	if utmDebugf != nil {
		utmDebugf(format, args...)
	}
}

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

func guessUTMVMIdentifierFromDisk(candidates []string) string {
	// If utmctl list is unavailable (TCC/SSH/no-login), we still can often "stat" known VM bundles
	// without enumerating the directory.
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	docsDir := filepath.Join(home, "Library", "Containers", "com.utmapp.UTM", "Data", "Documents")

	for _, name := range candidates {
		p := filepath.Join(docsDir, name+".utm")
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return name
		}
	}
	return ""
}

func guessUTMWindowsVMIdentifierFromDisk() string {
	// Common CI names (prefer exact casing used by your fleet).
	return guessUTMVMIdentifierFromDisk([]string{
		"ci-Windows",
		"ci-windows",
		"ci-os-windows",
		"ci-os-Windows",
	})
}

func guessUTMLinuxVMIdentifierFromDisk() string {
	// Common CI names (prefer exact casing used by your fleet).
	return guessUTMVMIdentifierFromDisk([]string{
		"ci-Linux",
		"ci-linux",
		"ci-os-linux",
		"ci-os-Linux",
		"ci-ubuntu",
		"ci-Ubuntu",
	})
}

func parseIPToken(s string) net.IP {
	t := strings.TrimSpace(s)
	t = strings.Trim(t, ",;")
	if t == "" {
		return nil
	}
	// Handle CIDR output like "192.168.64.10/24".
	if strings.Contains(t, "/") {
		if ip, _, err := net.ParseCIDR(t); err == nil && ip != nil {
			return ip
		}
		parts := strings.SplitN(t, "/", 2)
		t = parts[0]
	}
	// Handle zone suffixes like "fe80::1%en0" (not expected for IPv4, but harmless).
	if i := strings.Index(t, "%"); i >= 0 {
		t = t[:i]
	}
	ip := net.ParseIP(t)
	if ip == nil {
		return nil
	}
	return ip
}

func parseUTMCtlIPOutput(out string) (ipv4 string, any string) {
	// utmctl output is usually one IP per line, but we also accept tokens like:
	// "IP address: 192.168.64.10/24"
	lines := strings.Split(out, "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		for _, tok := range strings.Fields(ln) {
			ip := parseIPToken(tok)
			if ip == nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String(), ip4.String()
			}
			if any == "" {
				any = ip.String()
			}
		}
	}
	return "", any
}

func isUTMNotRunning(output string, err error) bool {
	s := strings.ToLower(strings.TrimSpace(output))
	if strings.Contains(s, "virtual machine is not running") {
		return true
	}
	// utmctl may return OSStatus error -2700 when VM isn't running.
	if strings.Contains(s, "osstatus error -2700") {
		return true
	}
	_ = err
	return false
}

func ensureUTMVMStartedBestEffort(identifier string) {
	id := strings.TrimSpace(identifier)
	if id == "" {
		return
	}
	utmLogf("[utm] start vm: id=%q", id)
	// Best effort: try both hide/non-hide to accommodate CI/headless differences.
	_ = utmctlStart(id, true)
	_ = utmctlStart(id, false)
}

func utmctlIPv4WithRetry(identifier string, timeout time.Duration) (string, error) {
	id := strings.TrimSpace(identifier)
	if id == "" {
		return "", fmt.Errorf("empty identifier")
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	deadline := time.Now().Add(timeout)
	var lastOut []byte
	var lastErr error
	attempt := 0

	for time.Now().Before(deadline) {
		attempt++
		utmLogf("[utm] ip-address attempt=%d id=%q", attempt, id)
		out, err := runUTMCtl([]string{"ip-address", "--hide", id}, 30*time.Second)
		lastOut, lastErr = out, err
		if err == nil {
			if ip4, any := parseUTMCtlIPOutput(string(out)); ip4 != "" {
				utmLogf("[utm] ip-address ok: id=%q ip=%s", id, ip4)
				return ip4, nil
			} else if any != "" {
				utmLogf("[utm] ip-address ok: id=%q ip=%s", id, any)
				return any, nil
			}
			utmLogf("[utm] ip-address output had no parseable ip: id=%q out=%q", id, strings.TrimSpace(string(out)))
			lastErr = fmt.Errorf("utmctl ip-address 未返回任何地址（identifier=%q）", id)
		} else if isUTMNotRunning(string(out), err) {
			utmLogf("[utm] vm not running yet: id=%q err=%v out=%q", id, err, strings.TrimSpace(string(out)))
			ensureUTMVMStartedBestEffort(id)
		} else {
			utmLogf("[utm] ip-address failed: id=%q err=%v out=%q", id, err, strings.TrimSpace(string(out)))
		}
		time.Sleep(2 * time.Second)
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("unknown error")
	}
	return "", fmt.Errorf("utmctl ip-address 失败: %w: %s", lastErr, string(lastOut))
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
	if id == "" {
		id = guessUTMWindowsVMIdentifierFromDisk()
	}
	// If utmctl list is unavailable (e.g. SSH session / no login), fall back to scanning.
	if id == "" {
		if ip, err := discoverWindowsVMIPv4ByScan(5985); err == nil {
			return ip, nil
		}
		return "", fmt.Errorf("未提供 UTM VM 标识：请设置 TRUSTINSTALL_UTM_WINDOWS_VM（或 TRUSTINSTALL_UTM_VM）为 VM 完整名称或 UUID；或确保存在一个以 %q 或 %q 开头的 Windows VM（例如 ci-Windows）；若在无登录/SSH 场景 utmctl 不可用，可设置 TRUSTINSTALL_WINDOWS_DISCOVERY_CIDRS 或手动设置 TRUSTINSTALL_WINDOWS_WINRM_ENDPOINT", defaultCIPrefixOS, defaultCIPrefixCI)
	}

	// Best effort: start VM first, then query IP.
	ensureUTMVMStartedBestEffort(id)
	utmLogf("[utm] discover windows ip via utmctl: id=%q", id)
	ip, err := utmctlIPv4WithRetry(id, 90*time.Second)
	if err != nil {
		utmLogf("[utm] discover windows ip failed, fallback to scan: err=%v", err)
		if ip2, scanErr := discoverWindowsVMIPv4ByScan(5985); scanErr == nil {
			return ip2, nil
		}
		return "", err
	}
	return ip, nil
}

func discoverUTMLinuxIPv4(identifier string) (string, error) {
	id := strings.TrimSpace(identifier)
	if id == "" {
		id = strings.TrimSpace(os.Getenv("TRUSTINSTALL_UTM_LINUX_VM"))
	}
	if id == "" {
		id = strings.TrimSpace(os.Getenv("TRUSTINSTALL_UTM_VM"))
	}
	if id == "" {
		// CI 默认：优先选择名称前缀为 ci-os 的 VM。
		vms, _ := utmctlListVMs()
		id = pickUTMLinuxVMIdentifier(vms)
	}
	if id == "" {
		id = guessUTMLinuxVMIdentifierFromDisk()
	}
	// If utmctl list is unavailable (e.g. SSH session / no login), fall back to scanning.
	if id == "" {
		if ip, err := discoverLinuxVMIPv4ByScan(22); err == nil {
			return ip, nil
		}
		return "", fmt.Errorf("未提供 UTM VM 标识：请设置 TRUSTINSTALL_UTM_LINUX_VM（或 TRUSTINSTALL_UTM_VM）为 VM 完整名称或 UUID；或确保存在一个以 %q 或 %q 开头的 Linux VM（例如 ci-Linux）；若在无登录/SSH 场景 utmctl 不可用，可设置 TRUSTINSTALL_LINUX_DISCOVERY_CIDRS 或手动设置 TRUSTINSTALL_LINUX_SSH_HOST", defaultCIPrefixOS, defaultCIPrefixCI)
	}

	// Best effort: start VM first, then query IP.
	ensureUTMVMStartedBestEffort(id)
	utmLogf("[utm] discover linux ip via utmctl: id=%q", id)
	ip, err := utmctlIPv4WithRetry(id, 90*time.Second)
	if err != nil {
		utmLogf("[utm] discover linux ip failed, fallback to scan: err=%v", err)
		if ip2, scanErr := discoverLinuxVMIPv4ByScan(22); scanErr == nil {
			return ip2, nil
		}
		return "", err
	}
	return ip, nil
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

func pickUTMLinuxVMIdentifier(vms []utmVM) string {
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

	// Prefer Linux VM in CI by name.
	for _, vm := range ci {
		name := strings.ToLower(strings.TrimSpace(vm.Name))
		if strings.Contains(name, "linux") || strings.Contains(name, "ubuntu") || strings.Contains(name, "debian") {
			return vm.Name
		}
	}
	if len(ci) == 1 {
		return ci[0].Name
	}
	if len(ci) > 1 {
		sort.Slice(ci, func(i, j int) bool { return ci[i].Name < ci[j].Name })
		return ci[0].Name
	}

	if len(vms) == 1 {
		return vms[0].Name
	}
	return ""
}

func utmctlListVMs() ([]utmVM, error) {
	// Try with --hide first (CI/headless), then without --hide.
	if vms, err := utmctlListVMsOnce(true); len(vms) > 0 || err == nil {
		if len(vms) > 0 {
			return vms, nil
		}
		// err == nil but no VMs: still try without --hide.
	}
	return utmctlListVMsOnce(false)
}

func utmctlListVMsOnce(hide bool) ([]utmVM, error) {
	args := []string{"list"}
	if hide {
		args = append(args, "--hide")
	}
	out, err := runUTMCtl(args, 20*time.Second)

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
	// utmctl 在某些场景（例如 SSH session、未登录）会返回非 0 退出码，但仍可能输出列表。
	// 这里优先信任解析结果，只要能解析出 VM 就忽略 err。
	if len(vms) > 0 {
		return vms, nil
	}
	if err != nil {
		return nil, err
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
		if id == "" {
			id = guessUTMWindowsVMIdentifierFromDisk()
		}
	}
	if id == "" {
		return "", fmt.Errorf("未提供 UTM VM 标识：请设置 TRUSTINSTALL_UTM_WINDOWS_VM")
	}

	// Best effort: ensure VM is started before exec.
	_ = utmctlStart(id, true)
	_ = utmctlStart(id, false)

	deadline := time.Now().Add(12 * time.Minute)
	var lastOut string
	var lastErr error
	for time.Now().Before(deadline) {
		out, err := utmctlExecOnce(id, true, cmdArgs...)
		if err == nil {
			return out, nil
		}
		lastOut, lastErr = out, err

		out2, err2 := utmctlExecOnce(id, false, cmdArgs...)
		if err2 == nil {
			return out2, nil
		}
		if strings.TrimSpace(out2) != "" {
			lastOut, lastErr = out2, err2
		}

		_ = utmctlStart(id, true)
		_ = utmctlStart(id, false)
		time.Sleep(5 * time.Second)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("unknown error")
	}
	return lastOut, fmt.Errorf("utmctl exec 超时: %w: %s", lastErr, lastOut)
}

func utmctlExecLinux(identifier string, cmdArgs ...string) (string, error) {
	id := strings.TrimSpace(identifier)
	if id == "" {
		id = strings.TrimSpace(os.Getenv("TRUSTINSTALL_UTM_LINUX_VM"))
	}
	if id == "" {
		id = strings.TrimSpace(os.Getenv("TRUSTINSTALL_UTM_VM"))
	}
	if id == "" {
		vms, _ := utmctlListVMs()
		id = pickUTMLinuxVMIdentifier(vms)
	}
	if id == "" {
		id = guessUTMLinuxVMIdentifierFromDisk()
	}
	if id == "" {
		return "", fmt.Errorf("未提供 UTM VM 标识：请设置 TRUSTINSTALL_UTM_LINUX_VM")
	}

	// Best effort: ensure VM is started before exec.
	_ = utmctlStart(id, true)
	_ = utmctlStart(id, false)

	deadline := time.Now().Add(12 * time.Minute)
	var lastOut string
	var lastErr error
	for time.Now().Before(deadline) {
		out, err := utmctlExecOnce(id, true, cmdArgs...)
		if err == nil {
			return out, nil
		}
		lastOut, lastErr = out, err

		out2, err2 := utmctlExecOnce(id, false, cmdArgs...)
		if err2 == nil {
			return out2, nil
		}
		if strings.TrimSpace(out2) != "" {
			lastOut, lastErr = out2, err2
		}

		_ = utmctlStart(id, true)
		_ = utmctlStart(id, false)
		time.Sleep(5 * time.Second)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("unknown error")
	}
	return lastOut, fmt.Errorf("utmctl exec 超时: %w: %s", lastErr, lastOut)
}

func utmctlExecOnce(identifier string, hide bool, cmdArgs ...string) (string, error) {
	args := []string{"exec"}
	if hide {
		args = append(args, "--hide")
	}
	args = append(args, identifier, "--cmd")
	args = append(args, cmdArgs...)
	out, err := runUTMCtl(args, 12*time.Minute)
	s := string(out)
	if err != nil {
		return s, err
	}
	if isUTMCtlEventError(s) {
		return s, fmt.Errorf("utmctl exec 返回 AppleEvent/OSStatus 错误（疑似未真正执行）")
	}
	return s, nil
}

func utmctlStart(identifier string, hide bool) error {
	args := []string{"start"}
	if hide {
		args = append(args, "--hide")
	}
	args = append(args, identifier)
	_, err := runUTMCtl(args, 2*time.Minute)
	return err
}
