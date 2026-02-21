//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDockerWindowsDockurIntegration(t *testing.T) {
	// dockur/windows runs a Windows VM via KVM. This only works on Linux hosts with /dev/kvm.
	if runtime.GOOS != "linux" {
		t.Skip("dockur/windows 需要 Linux + KVM(/dev/kvm)，当前宿主机不是 Linux，跳过")
	}
	if os.Getenv("TRUSTINSTALL_WINDOWS_INTEGRATION") == "" {
		t.Skip("未设置 TRUSTINSTALL_WINDOWS_INTEGRATION=1，跳过 Windows(dockur/windows) 集成测试")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("未找到 docker，跳过")
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		t.Skip("未找到 /dev/kvm（需要 KVM），跳过")
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("findRepoRoot err=%v", err)
	}

	tmp := t.TempDir()
	storage := filepath.Join(tmp, "storage")
	if err := os.MkdirAll(storage, 0o755); err != nil {
		t.Fatalf("mkdir storage err=%v", err)
	}

	oemInstallBat := filepath.Join(tmp, "install.bat")
	if err := os.WriteFile(oemInstallBat, []byte(windowsOEMInstallBat()), 0o644); err != nil {
		t.Fatalf("write install.bat err=%v", err)
	}

	image := strings.TrimSpace(os.Getenv("TRUSTINSTALL_DOCKUR_WINDOWS_IMAGE"))
	if image == "" {
		image = "dockurr/windows:latest"
	}
	version := strings.TrimSpace(os.Getenv("TRUSTINSTALL_DOCKUR_WINDOWS_VERSION"))
	if version == "" {
		version = "11"
	}

	// Resource knobs (override as needed).
	ram := strings.TrimSpace(os.Getenv("TRUSTINSTALL_DOCKUR_WINDOWS_RAM"))
	if ram == "" {
		ram = "6G"
	}
	cpu := strings.TrimSpace(os.Getenv("TRUSTINSTALL_DOCKUR_WINDOWS_CPU"))
	if cpu == "" {
		cpu = "4"
	}

	containerName := "trustinstall-dockur-win-it-" + fmt.Sprint(time.Now().UnixNano())
	args := []string{
		"run", "--rm", "--name", containerName,
		// Required for dockur/windows networking.
		"--cap-add", "NET_ADMIN",
		"--device", "/dev/kvm",
		"--device", "/dev/net/tun",
		// Persist output to host.
		"-v", storage + ":/storage",
		// OEM automation script + source checkout (copied into Windows as C:\\OEM\\...).
		"-v", oemInstallBat + ":/oem/install.bat:ro",
		"-v", repoRoot + ":/oem/src:ro",
		"-e", "VERSION=" + version,
		"-e", "RAM_SIZE=" + ram,
		"-e", "CPU_CORES=" + cpu,
		image,
	}

	// Start container in background.
	start := exec.Command("docker", append([]string{"run", "-d"}, args[2:]...)...)
	var startOut bytes.Buffer
	start.Stdout = &startOut
	start.Stderr = &startOut
	if err := start.Run(); err != nil {
		t.Fatalf("docker run -d failed: %v\n%s", err, startOut.String())
	}

	// Ensure cleanup.
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	})

	// Wait for OEM script to write result markers into /storage.
	okPath := filepath.Join(storage, "trustinstall-it.ok")
	failPath := filepath.Join(storage, "trustinstall-it.fail")
	logPath := filepath.Join(storage, "trustinstall-it.log")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
	defer cancel()
	for {
		if _, err := os.Stat(okPath); err == nil {
			if b, err := os.ReadFile(logPath); err == nil {
				t.Logf("windows OEM log:\n%s", string(b))
			}
			return
		}
		if _, err := os.Stat(failPath); err == nil {
			b, _ := os.ReadFile(logPath)
			t.Fatalf("windows integration failed; log:\n%s", string(b))
		}
		select {
		case <-ctx.Done():
			// Include docker logs for debugging.
			_ = exec.Command("docker", "logs", containerName).Run()
			b, _ := os.ReadFile(logPath)
			t.Fatalf("timeout waiting for windows integration result; log:\n%s", string(b))
		case <-time.After(5 * time.Second):
		}
	}
}

func windowsOEMInstallBat() string {
	// Note: This script runs inside Windows during/after setup. It writes logs to C:\\storage (mounted /storage).
	// It uses Go zip installer to avoid MSI UI.
	return strings.Join([]string{
		"@echo off",
		"setlocal enabledelayedexpansion",
		"set LOG=C:\\storage\\trustinstall-it.log",
		"echo [trustinstall-it] start > %LOG%",
		"echo [trustinstall-it] whoami: %USERNAME% >> %LOG%",
		"echo [trustinstall-it] preparing Go... >> %LOG%",
		"powershell -NoProfile -NonInteractive -Command \"try { $url='https://go.dev/dl/go1.25.5.windows-amd64.zip'; $out='C:\\\\storage\\\\go.zip'; Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out; Expand-Archive -Force -Path $out -DestinationPath 'C:\\\\'; Write-Output 'ok' } catch { Write-Output $_; exit 1 }\" >> %LOG% 2>>&1",
		"if errorlevel 1 (echo [trustinstall-it] Go install failed >> %LOG% & echo fail> C:\\storage\\trustinstall-it.fail & exit /b 1)",
		"set PATH=C:\\go\\bin;%PATH%",
		"where go >> %LOG% 2>>&1",
		"go version >> %LOG% 2>>&1",
		"echo [trustinstall-it] running go test (windows_integration)... >> %LOG%",
		"cd /d C:\\OEM\\src",
		"go test ./... -tags windows_integration -run TestWindowsInstallUninstall_SystemTrust -count=1 -v >> %LOG% 2>>&1",
		"if errorlevel 1 (echo [trustinstall-it] go test failed >> %LOG% & echo fail> C:\\storage\\trustinstall-it.fail & exit /b 1)",
		"echo [trustinstall-it] success >> %LOG%",
		"echo ok> C:\\storage\\trustinstall-it.ok",
		"exit /b 0",
	}, "\r\n") + "\r\n"
}
