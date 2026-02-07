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

func TestDockerLinuxIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("宿主机为 Windows 时不运行此 Docker 集成测试")
	}
	if os.Getenv("TRUSTINSTALL_INTEGRATION") == "" {
		t.Skip("未设置 TRUSTINSTALL_INTEGRATION=1，跳过 Docker 集成测试")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("未找到 docker，跳过")
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("findRepoRoot err=%v", err)
	}

	image := strings.TrimSpace(os.Getenv("TRUSTINSTALL_DOCKER_IMAGE"))
	if image == "" {
		// Match repo go.mod (go 1.25.5 as of now).
		image = "golang:1.25.5-bookworm"
	}
	cmdStr := strings.Join([]string{
		"set -euo pipefail",
		// In some images, `bash -l` may reset PATH and hide /usr/local/go/bin. Make it explicit.
		`export PATH="/go/bin:/usr/local/go/bin:$PATH"`,
		// Base image already includes ca-certificates tooling; avoid apt-get to keep the test resilient to network/repo issues.
		`go test ./... -tags linux_integration -run TestLinuxInstallUninstall_SystemTrust -count=1 -v`,
	}, " && ")

	args := []string{
		"run", "--rm",
		"-v", repoRoot + ":/src",
		"-w", "/src",
		image,
		"bash", "-c", cmdStr,
	}

	c := exec.Command("docker", args...)
	if testing.Verbose() {
		// 透传容器内输出，便于确认安装/信任/卸载流程确实发生。
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
	} else {
		var out bytes.Buffer
		c.Stdout = &out
		c.Stderr = &out
		if err := c.Run(); err != nil {
			t.Fatalf("docker run failed: %v\n%s", err, out.String())
		}
		return
	}
	if err := c.Run(); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", os.ErrNotExist
}
