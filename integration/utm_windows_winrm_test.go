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

	// 默认在 CI 机器上开启（你的 CI 服务器命名以 ci- 开头，且使用 UTM）。
	// 可通过显式设置 0/false/no/off 关闭。
	if v := os.Getenv("TRUSTINSTALL_WINDOWS_WINRM_INTEGRATION"); v != "" {
		if isFalseyEnv(v) {
			t.Skip("TRUSTINSTALL_WINDOWS_WINRM_INTEGRATION=false，跳过")
		}
	} else {
		if os.Getenv("CI") == "" && !isCIHostByName() {
			t.Skip("非 CI 环境且未设置 TRUSTINSTALL_WINDOWS_WINRM_INTEGRATION=1，跳过 UTM Windows WinRM 集成测试")
		}
	}

	endpoint := strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_WINRM_ENDPOINT"))
	user := strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_WINRM_USER"))
	if user == "" {
		user = "ci"
	}
	password := os.Getenv("TRUSTINSTALL_WINDOWS_WINRM_PASSWORD")
	if password == "" {
		password = "cipass"
	}
	repoDir := strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_REPO_DIR"))
	if repoDir == "" {
		// CI 默认仓库位置
		repoDir = `C:\src\trustinstall`
	}

	if endpoint == "" {
		// IP 获取失败时不要直接失败：仍可 fallback 到 utmctl exec 在 guest 内执行并完成 WinRM 配置。
		if ip, err := discoverUTMIPv4(""); err == nil && strings.TrimSpace(ip) != "" {
			endpoint = "http://" + ip + ":5985/wsman"
		} else if testing.Verbose() {
			t.Logf("自动获取 UTM IP 失败，将 fallback 到 utmctl exec: %v", err)
		}
	}

	// Prefer WinRM via pywinrm; if missing/unavailable in CI, fall back to utmctl exec.
	if endpoint != "" {
		if _, err := exec.LookPath("python3"); err == nil {
			_, thisFile, _, _ := runtime.Caller(0)
			scriptPath := filepath.Join(filepath.Dir(thisFile), "winrm_run.py")
			var out bytes.Buffer
			cmd := exec.Command("python3",
				scriptPath,
				"--endpoint", endpoint,
				"--user", user,
				"--password", password,
				"--repo-dir", repoDir,
			)
			cmd.Stdout = &out
			cmd.Stderr = &out
			if err := cmd.Run(); err == nil {
				if testing.Verbose() {
					t.Logf("windows output:\n%s", out.String())
				}
				return
			} else if testing.Verbose() {
				t.Logf("WinRM 运行失败，尝试 fallback 到 utmctl exec：%v\n%s", err, out.String())
			}
		}
	}

	// Fallback: use utmctl exec to configure and run tests inside guest.
	if _, err := os.Stat(utmctlPath()); err != nil {
		t.Skipf("未找到 utmctl（%s），且 WinRM 不可用，跳过", utmctlPath())
	}

	ps := strings.Join([]string{
		`$ErrorActionPreference = 'Stop'`,
		// Best-effort: enable WinRM for future runs.
		`try { winrm quickconfig -q } catch {}`,
		`try { Enable-PSRemoting -Force } catch {}`,
		`try { netsh advfirewall firewall add rule name="WinRM HTTP 5985" dir=in action=allow protocol=TCP localport=5985 } catch {}`,
		// Ensure Go exists; download matching arch zip if missing.
		`if (-not (Get-Command go -ErrorAction SilentlyContinue)) {`,
		`  $arch = $env:PROCESSOR_ARCHITECTURE`,
		`  $goarch = 'amd64'`,
		`  if ($arch -match 'ARM64') { $goarch = 'arm64' }`,
		`  $ver = '1.25.5'`,
		`  $zip = "go$ver.windows-$goarch.zip"`,
		`  $url = "https://go.dev/dl/$zip"`,
		`  $out = "C:\Temp\$zip"`,
		`  New-Item -ItemType Directory -Force -Path C:\Temp | Out-Null`,
		`  Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out`,
		`  if (Test-Path C:\go) { Remove-Item -Recurse -Force C:\go }`,
		`  Expand-Archive -Force -Path $out -DestinationPath C:\`,
		`}`,
		`$env:PATH = "C:\go\bin;" + $env:PATH`,
		`Set-Location -LiteralPath ` + psSingleQuote(repoDir),
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
}

// helpers live in powershell.go
