//go:build integration

package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestUTMWindowsSSHIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("宿主机为 Windows 时跳过")
	}
	if os.Getenv("TRUSTINSTALL_WINDOWS_SSH_INTEGRATION") == "" {
		t.Skip("未设置 TRUSTINSTALL_WINDOWS_SSH_INTEGRATION=1，跳过 UTM Windows SSH 集成测试")
	}

	host := strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_SSH_HOST"))
	user := strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_SSH_USER"))
	if user == "" {
		user = "ci"
	}
	repoDir := strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_REPO_DIR"))
	if repoDir == "" {
		t.Fatalf("缺少环境变量：TRUSTINSTALL_WINDOWS_REPO_DIR")
	}
	if host == "" {
		ip, err := discoverUTMIPv4("")
		if err != nil {
			t.Fatalf("自动获取 UTM IP 失败: %v", err)
		}
		host = ip
	}

	port := strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_SSH_PORT"))
	keyPath := strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_SSH_KEY"))
	extra := strings.Fields(strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_SSH_EXTRA_ARGS")))

	if _, err := exec.LookPath("ssh"); err != nil {
		// CI 兜底：如果宿主机没有 ssh，就用 utmctl exec 在 guest 内直接执行。
		if _, err := os.Stat(utmctlPath()); err != nil {
			t.Skipf("未找到 ssh 且 utmctl 不可用（%s），跳过", utmctlPath())
		}
		ps := strings.Join([]string{
			`$ErrorActionPreference = 'Stop'`,
			fmt.Sprintf(`Set-Location -LiteralPath %s`, psSingleQuote(repoDir)),
			`go version`,
			`go test ./... -tags windows_integration -run TestWindowsInstallUninstall_SystemTrust -count=1 -v`,
		}, "\n")
		encoded := encodePowerShellEncodedCommand(ps)
		out, err := utmctlExec("", "powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
		if err != nil {
			t.Fatalf("utmctl exec 执行失败: %v\n%s", err, out)
		}
		if testing.Verbose() {
			t.Logf("windows output:\n%s", out)
		}
		return
	}

	ps := strings.Join([]string{
		`$ErrorActionPreference = 'Stop'`,
		fmt.Sprintf(`Set-Location -LiteralPath %s`, psSingleQuote(repoDir)),
		`Write-Output "[trustinstall-ssh-it] go version:"`,
		`go version`,
		`Write-Output "[trustinstall-ssh-it] running windows_integration tests..."`,
		`go test ./... -tags windows_integration -run TestWindowsInstallUninstall_SystemTrust -count=1 -v`,
	}, "\n")
	encoded := encodePowerShellEncodedCommand(ps)

	sshArgs := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
	}
	if port != "" {
		sshArgs = append(sshArgs, "-p", port)
	}
	if keyPath != "" {
		sshArgs = append(sshArgs, "-i", keyPath)
	}
	sshArgs = append(sshArgs, extra...)
	sshArgs = append(sshArgs, fmt.Sprintf("%s@%s", user, host),
		"powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded,
	)

	var out bytes.Buffer
	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		t.Fatalf("ssh 执行失败: %v\n%s", err, out.String())
	}
	if testing.Verbose() {
		t.Logf("windows output:\n%s", out.String())
	}
}

// helpers live in powershell.go
