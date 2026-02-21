//go:build integration || all_platform

package integration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestDockerLinuxIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("宿主机为 Windows 时不运行此 Docker 集成测试")
	}

	mustRun := false
	if v := strings.TrimSpace(os.Getenv("TRUSTINSTALL_LINUX_DOCKER_INTEGRATION")); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			t.Fatalf("TRUSTINSTALL_LINUX_DOCKER_INTEGRATION=%q 非法（需要 true/false/1/0）", v)
		}
		mustRun = true
		if !enabled {
			t.Skip("TRUSTINSTALL_LINUX_DOCKER_INTEGRATION=false，跳过")
		}
	} else if os.Getenv("TRUSTINSTALL_INTEGRATION") == "" {
		t.Skip("未设置 TRUSTINSTALL_LINUX_DOCKER_INTEGRATION=1（或 TRUSTINSTALL_INTEGRATION=1），跳过")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		if mustRun {
			t.Fatalf("未找到 docker：%v", err)
		}
		t.Skip("未找到 docker，跳过")
	}
	info := exec.Command("docker", "info", "--format", "{{.ServerVersion}}")
	var infoOut bytes.Buffer
	info.Stdout = &infoOut
	info.Stderr = &infoOut
	if err := info.Run(); err != nil {
		msg := strings.TrimSpace(infoOut.String())
		if msg == "" {
			if mustRun {
				t.Fatalf("docker daemon 不可用: %v", err)
			}
			t.Skipf("docker daemon 不可用，跳过: %v", err)
		}
		if mustRun {
			t.Fatalf("docker daemon 不可用: %v: %s", err, msg)
		}
		t.Skipf("docker daemon 不可用，跳过: %v: %s", err, msg)
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
	t.Logf("docker image=%s", image)

	cmdStr := strings.Join([]string{
		"set -euo pipefail",
		// In some images, `bash -l` may reset PATH and hide /usr/local/go/bin. Make it explicit.
		`export PATH="/go/bin:/usr/local/go/bin:$PATH"`,
		// Base image already includes ca-certificates tooling; avoid apt-get to keep the test resilient to network/repo issues.
		`go test ./... -tags linux_integration -run TestLinuxInstallUninstall_SystemTrust -count=1 -v`,
	}, " && ")

	args := []string{
		"run", "--rm",
		"--user", "0:0",
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
