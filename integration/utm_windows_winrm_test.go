//go:build integration

package integration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUTMWindowsWinRMIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("宿主机为 Windows 时跳过")
	}
	if os.Getenv("TRUSTINSTALL_WINDOWS_WINRM_INTEGRATION") == "" {
		t.Skip("未设置 TRUSTINSTALL_WINDOWS_WINRM_INTEGRATION=1，跳过 UTM Windows WinRM 集成测试")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("未找到 python3，跳过")
	}

	endpoint := strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_WINRM_ENDPOINT"))
	user := strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_WINRM_USER"))
	password := os.Getenv("TRUSTINSTALL_WINDOWS_WINRM_PASSWORD")
	repoDir := strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_REPO_DIR"))
	if endpoint == "" || user == "" || password == "" || repoDir == "" {
		t.Fatalf("缺少环境变量：TRUSTINSTALL_WINDOWS_WINRM_ENDPOINT/TRUSTINSTALL_WINDOWS_WINRM_USER/TRUSTINSTALL_WINDOWS_WINRM_PASSWORD/TRUSTINSTALL_WINDOWS_REPO_DIR")
	}

	script := filepath.Join("integration", "winrm_run.py")
	args := []string{
		script,
		"--endpoint", endpoint,
		"--user", user,
		"--password", password,
		"--repo-dir", repoDir,
	}

	var out bytes.Buffer
	cmd := exec.Command("python3", args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		// If pywinrm is missing, the helper exits with 2. Treat it as skip to keep the suite friendly.
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 2 {
			t.Skipf("pywinrm 不可用，跳过（输出：%s）", out.String())
		}
		t.Fatalf("winrm helper failed: %v\n%s", err, out.String())
	}
	if testing.Verbose() {
		t.Logf("windows output:\n%s", out.String())
	}
}
