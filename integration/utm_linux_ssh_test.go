//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestUTMLinuxIntegration(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("仅在 macOS + UTM 场景运行（宿主机=%s）", runtime.GOOS)
	}

	oldDebugf := utmDebugf
	utmDebugf = func(format string, args ...any) {
		t.Logf(format, args...)
	}
	t.Cleanup(func() { utmDebugf = oldDebugf })

	oldSSHDebugf := sshDebugf
	sshDebugf = func(format string, args ...any) {
		t.Logf(format, args...)
	}
	t.Cleanup(func() { sshDebugf = oldSSHDebugf })

	// 默认在 CI 机器上开启（你的 CI 服务器命名以 ci- 开头，且使用 UTM）。
	// 可通过显式设置 0/false/no/off 关闭。
	enabled := false
	if v := os.Getenv("TRUSTINSTALL_LINUX_INTEGRATION"); v != "" {
		if isFalseyEnv(v) {
			t.Skip("TRUSTINSTALL_LINUX_INTEGRATION=false，跳过")
		}
		enabled = true
	} else {
		if os.Getenv("CI") == "" && !isCIHostByName() {
			t.Skip("非 CI 环境且未设置 TRUSTINSTALL_LINUX_INTEGRATION=1，跳过 UTM Linux 集成测试")
		}
		enabled = true
	}
	if !enabled {
		t.Skip("未启用")
	}

	host := strings.TrimSpace(os.Getenv("TRUSTINSTALL_LINUX_SSH_HOST"))
	user := strings.TrimSpace(os.Getenv("TRUSTINSTALL_LINUX_SSH_USER"))
	if user == "" {
		user = "ci"
	}
	if os.Getenv("TRUSTINSTALL_LINUX_SSH_PASSWORD") == "" && user == "ci" {
		// CI 约定：默认账号 ci/cipass。可通过显式设置 TRUSTINSTALL_LINUX_SSH_PASSWORD 覆盖。
		_ = os.Setenv("TRUSTINSTALL_LINUX_SSH_PASSWORD", "cipass")
		t.Logf("[linux-it] using default ssh password for user=ci (cipass); override via TRUSTINSTALL_LINUX_SSH_PASSWORD")
	}
	if os.Getenv("TRUSTINSTALL_LINUX_SUDO_PASSWORD") == "" && os.Getenv("TRUSTINSTALL_LINUX_SSH_PASSWORD") != "" {
		// 如果 sudo -n 在非交互/PTY 场景下行为不一致，使用同一套凭据兜底。
		_ = os.Setenv("TRUSTINSTALL_LINUX_SUDO_PASSWORD", os.Getenv("TRUSTINSTALL_LINUX_SSH_PASSWORD"))
		t.Logf("[linux-it] TRUSTINSTALL_LINUX_SUDO_PASSWORD 未设置，默认复用 SSH 密码；可通过 TRUSTINSTALL_LINUX_SUDO_PASSWORD 覆盖")
	}
	repoDir := strings.TrimSpace(os.Getenv("TRUSTINSTALL_LINUX_REPO_DIR"))
	if repoDir == "" {
		// CI 约定：默认仓库目录。
		repoDir = "/home/ci/trustinstall"
		t.Logf("[linux-it] TRUSTINSTALL_LINUX_REPO_DIR 未设置，默认使用 %s", repoDir)
	}

	portStr := strings.TrimSpace(os.Getenv("TRUSTINSTALL_LINUX_SSH_PORT"))
	if portStr == "" {
		portStr = "22"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		t.Fatalf("非法端口：TRUSTINSTALL_LINUX_SSH_PORT=%q", portStr)
	}

	if host == "" {
		t.Logf("[linux-it] discover host ip via utmctl/scan...")
		ip, err := discoverUTMLinuxIPv4("")
		if err != nil {
			t.Fatalf("自动获取 UTM Linux IP 失败: %v", err)
		}
		host = ip
	}
	t.Logf("[linux-it] target=%s@%s:%d repoDir=%s", user, host, port, repoDir)

	goProxy := strings.TrimSpace(os.Getenv("GOPROXY"))
	if goProxy == "" {
		goProxy = "https://goproxy.cn,direct"
	}
	goSumDB := strings.TrimSpace(os.Getenv("GOSUMDB"))
	if goSumDB == "" {
		goSumDB = "sum.golang.google.cn"
	}
	goToolchain := strings.TrimSpace(os.Getenv("GOTOOLCHAIN"))
	if goToolchain == "" {
		goToolchain = "auto"
	}

	rootScript := strings.Join([]string{
		"set -euo pipefail",
		fmt.Sprintf("cd %s", shellQuote(repoDir)),
		`if [ ! -f go.mod ]; then echo "[trustinstall-linux-it] ERROR: missing go.mod in repo dir (set TRUSTINSTALL_LINUX_REPO_DIR to the real repo path)" >&2; exit 3; fi`,
		fmt.Sprintf("export GOPROXY=%s", shellQuote(goProxy)),
		fmt.Sprintf("export GOSUMDB=%s", shellQuote(goSumDB)),
		fmt.Sprintf("export GOTOOLCHAIN=%s", shellQuote(goToolchain)),
		`echo "[trustinstall-linux-it] go version:"`,
		"go version",
		`echo "[trustinstall-linux-it] running linux_integration tests..."`,
		// Make PATH explicit; some CI images/users may not have it in non-interactive shells.
		`export PATH="/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:$PATH"`,
		`go test ./... -tags linux_integration -run TestLinuxInstallUninstall_SystemTrust -count=1 -v`,
	}, "\n")

	runAsRootCmd := strings.Join([]string{
		"set -euo pipefail",
		`if [ "$(id -u)" -eq 0 ]; then`,
		"  exec bash -lc " + shellQuote(rootScript),
		"fi",
		`if ! command -v sudo >/dev/null 2>&1; then`,
		`  echo "[trustinstall-linux-it] ERROR: need root (run as root or install/configure sudo)" >&2; exit 2`,
		"fi",
		// First try non-interactive sudo.
		"set +e",
		"sudo -n bash -lc " + shellQuote(rootScript),
		`rc=$?`,
		"set -e",
		`if [ "$rc" -eq 0 ]; then exit 0; fi`,
		`echo "[trustinstall-linux-it] sudo -n failed (rc=$rc); try sudo -S" >&2`,
		// Diagnostics (best-effort; should not prompt).
		`(sudo -n -l 2>&1 || true) | sed 's/^/[trustinstall-linux-it] sudo -l: /' >&2`,
		// Fallback: sudo -S with password via stdin (provided by the ssh client).
		"exec sudo -S -p '' bash -lc " + shellQuote(rootScript),
	}, "\n")

	// VM 刚启动时 sshd 可能还没起来；若 VM 根本没装 sshd，则会一直 connection refused。
	// 默认策略：等待端口短暂就绪；不就绪则自动 fallback 到 utmctl exec（如果可用）。
	t.Logf("[linux-it] waiting for tcp port %d...", port)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := waitForTCPPort(ctx, host, port, 1*time.Second); err != nil {
		if _, statErr := os.Stat(utmctlPath()); statErr == nil {
			t.Logf("[linux-it] ssh port not ready (%v); falling back to utmctl exec", err)
			out, err2 := utmctlExecLinux("", "bash", "-lc", runAsRootCmd)
			if err2 != nil {
				t.Fatalf("utmctl exec 执行失败: %v\n%s", err2, out)
			}
			if testing.Verbose() {
				t.Logf("linux output:\n%s", out)
			}
			return
		}
		t.Fatalf("SSH 端口不可用（%v），且 utmctl 不可用（%s）。请在 Linux VM 安装/启用 sshd，或提供可用的 utmctl。", err, utmctlPath())
	}

	t.Logf("[linux-it] run ssh(go) remote command...")
	t.Logf("[linux-it] ensure repo exists on VM...")
	runCmd := "bash -lc " + shellQuote(runAsRootCmd)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel2()

	goModPath := repoDir + "/go.mod"
	checkInner := fmt.Sprintf("test -f %s", shellQuote(goModPath))
	checkCmd := "bash -lc " + shellQuote(checkInner)
	t.Logf("[linux-it] check remote go.mod: %s", goModPath)
	ctxCheck, cancelCheck := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCheck()
	outC, checkErr := runSSHCommandGoWithOptions(ctxCheck, host, port, user, checkCmd, sshRunOptions{})
	if checkErr != nil {
		if ctxCheck.Err() != nil {
			t.Logf("[linux-it] check remote go.mod timeout (%v), treat as missing and upload", ctxCheck.Err())
		} else {
			t.Logf("[linux-it] check remote go.mod failed: %v\n%s", checkErr, outC)
		}
		t.Logf("[linux-it] repo missing on VM, uploading from host workspace...")
		repoRoot, err := findRepoRoot()
		if err != nil {
			t.Fatalf("findRepoRoot err=%v", err)
		}
		outU, errU := uploadRepoToLinuxVM(ctx2, host, port, user, repoDir, repoRoot)
		if errU != nil {
			t.Fatalf("上传仓库到 Linux VM 失败: %v\n%s", errU, outU)
		}
	}

	// Heartbeat to make long-running remote commands observable in CI logs.
	doneHB := make(chan struct{})
	start := time.Now()
	go func() {
		tk := time.NewTicker(30 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-doneHB:
				return
			case <-tk.C:
				t.Logf("[linux-it] still running remote go test... elapsed=%s", time.Since(start).Round(time.Second))
			}
		}
	}()

	sudoStdin := "\n"
	if pw := os.Getenv("TRUSTINSTALL_LINUX_SUDO_PASSWORD"); pw != "" {
		// Do not log the actual password; only feed it to sudo -S if used.
		sudoStdin = pw + "\n"
	}
	out, err := runSSHCommandGoWithOptions(ctx2, host, port, user, runCmd, sshRunOptions{
		stdin:      strings.NewReader(sudoStdin),
		requestPty: true, // sudo-rs/策略在无 tty 时可能异常
		streamOut:  true, // stream remote output to logs
	})
	close(doneHB)
	if err != nil {
		// 认证失败/连接层错误时给出更好的兜底：fallback 到 utmctl exec。
		if isSSHAuthError(err) || strings.Contains(err.Error(), "未配置 SSH 认证方式") || shouldFallbackFromSSHError(out) || shouldFallbackFromSSHError(err.Error()) {
			if _, statErr := os.Stat(utmctlPath()); statErr == nil {
				t.Logf("[linux-it] ssh(go) failed (%v); falling back to utmctl exec", err)
				out2, err2 := utmctlExecLinux("", "bash", "-lc", runAsRootCmd)
				if err2 != nil {
					t.Fatalf("utmctl exec 执行失败: %v\n%s", err2, out2)
				}
				if testing.Verbose() {
					t.Logf("linux output:\n%s", out2)
				}
				return
			}
		}
		t.Fatalf("ssh(go) 执行失败: %v\n%s", err, out)
	}
	if testing.Verbose() {
		t.Logf("linux output:\n%s", out)
	}
}

func uploadRepoToLinuxVM(ctx context.Context, host string, port int, user, repoDir, localRepoRoot string) (string, error) {
	if strings.TrimSpace(repoDir) == "" || repoDir == "/" {
		return "", fmt.Errorf("非法 repoDir=%q", repoDir)
	}
	// Use a stream to avoid buffering the whole archive in memory.
	pr, pw := io.Pipe()
	go func() {
		err := tarGzDirToWriter(pw, localRepoRoot)
		_ = pw.CloseWithError(err)
	}()

	remoteScript := strings.Join([]string{
		"set -euo pipefail",
		"repo=" + shellQuote(repoDir),
		`tmp="$(mktemp -d)"`,
		`tar -xzf - -C "$tmp"`,
		`if [ ! -f "$tmp/go.mod" ]; then echo "[trustinstall-linux-it] ERROR: uploaded archive missing go.mod" >&2; exit 4; fi`,
		// Replace directory for /home/* to avoid mixing old/new files.
		`case "$repo" in`,
		`  /home/*) rm -rf -- "$repo"; mkdir -p "$(dirname "$repo")"; mv "$tmp" "$repo" ;;`,
		`  *) mkdir -p "$repo"; cp -a "$tmp/." "$repo/"; rm -rf -- "$tmp" ;;`,
		`esac`,
		`echo "[trustinstall-linux-it] repo uploaded to $repo"`,
	}, "\n")

	cmd := "bash -lc " + shellQuote(remoteScript)
	return runSSHCommandGoWithStdin(ctx, host, port, user, cmd, pr)
}

func waitForTCPPort(ctx context.Context, host string, port int, interval time.Duration) error {
	if interval <= 0 {
		interval = 1 * time.Second
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	for {
		d := net.Dialer{Timeout: 500 * time.Millisecond}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func shouldFallbackFromSSHError(output string) bool {
	s := strings.ToLower(output)
	if strings.Contains(s, "connection refused") {
		return true
	}
	if strings.Contains(s, "operation timed out") || strings.Contains(s, "timed out") {
		return true
	}
	if strings.Contains(s, "no route to host") {
		return true
	}
	if strings.Contains(s, "network is unreachable") {
		return true
	}
	return false
}
