//go:build integration || all_platform

package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

	if endpoint == "" {
		// IP 获取失败时不要直接失败：仍可 fallback 到 utmctl exec 在 guest 内执行并完成 WinRM 配置。
		if ip, err := discoverUTMIPv4(""); err == nil && strings.TrimSpace(ip) != "" {
			endpoint = "http://" + ip + ":5985/wsman"
		} else if testing.Verbose() {
			t.Logf("自动获取 UTM IP 失败，将 fallback 到 utmctl exec: %v", err)
		}
	}

	// Prefer WinRM; if unavailable in CI, fall back to utmctl exec.
	if endpoint != "" {
		var repoZipURL string
		var stopServer func()
		if repoDir == "" {
			u, stop, err := startRepoZipServerForWindows(endpoint)
			if err != nil {
				t.Fatalf("启动 repo zip server 失败: %v", err)
			}
			repoZipURL = u
			stopServer = stop
			defer stopServer()
			if testing.Verbose() {
				t.Logf("repo zip url=%s", repoZipURL)
			}
		}

		ps := strings.Join([]string{
			`$ErrorActionPreference = 'Stop'`,
			`$ProgressPreference = 'SilentlyContinue'`,
			`$env:GOPROXY = 'https://proxy.golang.com.cn,https://goproxy.cn,https://goproxy.io,direct'`,
			`$env:GOSUMDB = 'sum.golang.google.cn'`,
			`$env:PATH = "C:\go\bin;" + $env:PATH`,
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
			`  if (Get-Command curl.exe -ErrorAction SilentlyContinue) {`,
			`    curl.exe -L $url -o $out --max-time 600`,
			`  } else {`,
			`    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out`,
			`  }`,
			`  if (Test-Path C:\go) { Remove-Item -Recurse -Force C:\go }`,
			`  Expand-Archive -Force -Path $out -DestinationPath C:\`,
			`}`,
			`$env:PATH = "C:\go\bin;" + $env:PATH`,
			`$repoDir = ` + psSingleQuote(repoDir),
			`$repoZipUrl = ` + psSingleQuote(repoZipURL),
			`if ((-not $repoDir) -or (-not (Test-Path -LiteralPath $repoDir))) {`,
			`  if (-not $repoZipUrl) { Write-Output "[trustinstall-winrm-it] ERROR: missing repo"; exit 2 }`,
			`  $zipPath = "C:\Temp\trustinstall-src.zip"`,
			`  New-Item -ItemType Directory -Force -Path C:\Temp | Out-Null`,
			`  curl.exe -L $repoZipUrl -o $zipPath --max-time 600`,
			`  $extractDir = Join-Path C:\Temp ("trustinstall-src-" + [guid]::NewGuid().ToString("N"))`,
			`  New-Item -ItemType Directory -Force -Path $extractDir | Out-Null`,
			`  Expand-Archive -Force -Path $zipPath -DestinationPath $extractDir`,
			`  $repoDir = $extractDir`,
			`}`,
			`Set-Location -LiteralPath $repoDir`,
			`Write-Output "[trustinstall-winrm-it] go version:"`,
			`go version`,
			`Write-Output "[trustinstall-winrm-it] running windows_integration tests..."`,
			`go test ./... -tags windows_integration -run TestWindowsInstallUninstall_SystemTrust -count=1 -v`,
		}, "\n")
		encoded := encodePowerShellEncodedCommand(ps)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		res, err := runWinRMEncodedPowerShell(ctx, endpoint, user, password, encoded)
		if err == nil {
			if testing.Verbose() {
				t.Logf("windows output:\n%s%s", res.Stdout, res.Stderr)
			}
			return
		}
		if testing.Verbose() {
			t.Logf("WinRM 运行失败，尝试 fallback 到 utmctl exec：%v\n%s%s", err, res.Stdout, res.Stderr)
		}
	}

	// Fallback: use utmctl exec to configure and run tests inside guest.
	if _, err := os.Stat(utmctlPath()); err != nil {
		t.Skipf("未找到 utmctl（%s），且 WinRM 不可用，跳过", utmctlPath())
	}

	ps := strings.Join([]string{
		`$ErrorActionPreference = 'Stop'`,
		`$ProgressPreference = 'SilentlyContinue'`,
		// Best-effort: enable WinRM for future runs.
		`try { winrm quickconfig -q } catch {}`,
		`try { Enable-PSRemoting -Force } catch {}`,
		`try { netsh advfirewall firewall add rule name="WinRM HTTP 5985" dir=in action=allow protocol=TCP localport=5985 } catch {}`,
		`$env:PATH = "C:\go\bin;" + $env:PATH`,
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
		`  if (Get-Command curl.exe -ErrorAction SilentlyContinue) {`,
		`    curl.exe -L $url -o $out --max-time 600`,
		`  } else {`,
		`    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out`,
		`  }`,
		`  if (Test-Path C:\go) { Remove-Item -Recurse -Force C:\go }`,
		`  Expand-Archive -Force -Path $out -DestinationPath C:\`,
		`}`,
		`Write-Output "[trustinstall-utmctl-it] go version:"`,
		`go version`,
		`Write-Output "[trustinstall-utmctl-it] running windows_integration tests..."`,
		// Prefer local repo if provided and exists.
		`$repoDir = ` + psSingleQuote(repoDir),
		`if ($repoDir -and (Test-Path -LiteralPath $repoDir)) {`,
		`  Set-Location -LiteralPath $repoDir`,
		`  go test ./... -tags windows_integration -run TestWindowsInstallUninstall_SystemTrust -count=1 -v`,
		`} else { Write-Output "[trustinstall-utmctl-it] ERROR: missing TRUSTINSTALL_WINDOWS_REPO_DIR"; exit 2 }`,
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

func startRepoZipServerForWindows(endpoint string) (string, func(), error) {
	hostIPOverride := strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_HOST_IP"))
	guestIP := ""
	if u, err := url.Parse(endpoint); err == nil {
		h := u.Hostname()
		if net.ParseIP(h) != nil {
			guestIP = h
		}
	}

	hostIP := hostIPOverride
	if hostIP == "" && guestIP != "" {
		hostIP = pickLocalIPv4InSame24(guestIP)
	}
	if hostIP == "" {
		return "", nil, fmt.Errorf("无法确定宿主机 IP（guest=%q），请设置 TRUSTINSTALL_WINDOWS_HOST_IP", guestIP)
	}

	// Create repo zip from git-tracked files only (avoid huge untracked artifacts).
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Dir(filepath.Dir(thisFile))
	tmpDir, err := os.MkdirTemp("", "trustinstall-repozip-*")
	if err != nil {
		return "", nil, err
	}
	zipPath := filepath.Join(tmpDir, "trustinstall-src.zip")

	if _, err := exec.LookPath("git"); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("未找到 git，无法生成 repo zip")
	}
	// Use `git -C <root> archive` to avoid relying on current working dir (go test runs in ./integration).
	archiveCmd := exec.Command("git", "-C", repoRoot, "archive", "--format=zip", "-o", zipPath, "HEAD")
	if out, err := archiveCmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("git archive 失败: %w: %s", err, string(out))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/trustinstall-src.zip", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, zipPath)
	})

	ln, err := net.Listen("tcp", net.JoinHostPort(hostIP, "0"))
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, err
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() { _ = srv.Serve(ln) }()

	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = os.RemoveAll(tmpDir)
	}

	addr := ln.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		stop()
		return "", nil, err
	}

	return fmt.Sprintf("http://%s:%s/trustinstall-src.zip", hostIP, port), stop, nil
}

func pickLocalIPv4InSame24(guestIPv4 string) string {
	ip := net.ParseIP(strings.TrimSpace(guestIPv4)).To4()
	if ip == nil {
		return ""
	}
	prefix := fmt.Sprintf("%d.%d.%d.", ip[0], ip[1], ip[2])
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		var hostIP net.IP
		switch v := a.(type) {
		case *net.IPNet:
			hostIP = v.IP
		case *net.IPAddr:
			hostIP = v.IP
		}
		if hostIP == nil {
			continue
		}
		h4 := hostIP.To4()
		if h4 == nil {
			continue
		}
		s := h4.String()
		if strings.HasPrefix(s, prefix) {
			return s
		}
	}
	return ""
}
