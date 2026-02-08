//go:build integration || all_platform

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LubyRuffy/trustinstall"
)

func TestMITMDynamicLeafCertificate(t *testing.T) {
	if allPlatform {
		if runtime.GOOS != "darwin" {
			t.Skipf("all_platform 仅支持在 macOS 宿主机上通过 UTM 执行（宿主机=%s）", runtime.GOOS)
		}
		runMITMViaUTMAllPlatforms(t)
		return
	}

	if os.Getenv("TRUSTINSTALL_INTEGRATION") == "" {
		t.Skip("未设置 TRUSTINSTALL_INTEGRATION=1，跳过网络集成测试")
	}

	const target = "https://ip.bmh.im/c"

	tmp := t.TempDir()
	_, _, caCert, err := trustinstall.EnsureCAFiles(tmp, "mitm-ca", "mitm-ca")
	if err != nil {
		t.Fatalf("EnsureCAFiles err=%v", err)
	}

	deleteSame := false
	ti, err := trustinstall.New(trustinstall.Options{
		Dir:          tmp,
		FileBaseName: "mitm-ca",
		CommonName:   "mitm-ca",
		DeleteSame:   &deleteSame,
	})
	if err != nil {
		t.Fatalf("trustinstall.New err=%v", err)
	}

	p := newMITMProxy(ti, 1<<20)
	proxyURL, closeProxy := startLocalProxy(t, p)
	t.Cleanup(closeProxy)
	if testing.Verbose() {
		t.Logf("proxy=%s target=%s", proxyURL.String(), target)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: false,
		// Go 1.25: 显式禁用 HTTP/2，避免与最小实现的 MITM 代理不兼容。
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	t.Cleanup(tr.CloseIdleConnections)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequest err=%v", err)
	}

	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatalf("GET via proxy err=%v", err)
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		t.Fatalf("read body err=%v", readErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		t.Fatalf("unexpected status=%d body=%q", resp.StatusCode, string(body))
	}
	if len(bytes.TrimSpace(body)) == 0 {
		t.Fatalf("empty response body, status=%d", resp.StatusCode)
	}

	rec, ok := p.waitFirstRecord(10 * time.Second)
	if !ok {
		t.Fatalf("proxy did not record any decrypted HTTPS traffic")
	}
	if testing.Verbose() {
		// 只打印摘要，避免把不必要的敏感信息刷屏。
		t.Logf("decrypted=%s %s status=%s resp_bytes=%d", rec.Method, rec.URL, rec.Status, len(rec.RespBody))
	}
	if rec.Proto != "HTTPS" {
		t.Fatalf("unexpected record proto=%s", rec.Proto)
	}
	if rec.Method != http.MethodGet {
		t.Fatalf("unexpected record method=%s", rec.Method)
	}
	if rec.URL != target {
		t.Fatalf("unexpected record url=%s", rec.URL)
	}
	if len(rec.RespBody) == 0 {
		t.Fatalf("proxy recorded empty response body (decrypted)")
	}
}

func runMITMViaUTMAllPlatforms(t *testing.T) {
	t.Helper()

	if _, err := os.Stat(utmctlPath()); err != nil {
		t.Skipf("未找到 utmctl（%s），无法通过 UTM 执行三平台集成测试", utmctlPath())
	}

	oldDebugf := utmDebugf
	utmDebugf = func(format string, args ...any) { t.Logf(format, args...) }
	t.Cleanup(func() { utmDebugf = oldDebugf })

	oldSSHDebugf := sshDebugf
	sshDebugf = func(format string, args ...any) { t.Logf(format, args...) }
	t.Cleanup(func() { sshDebugf = oldSSHDebugf })

	// 约定：all_platform 模式下，仍然复用 guest 内的本地集成测试逻辑（-tags integration），
	// 但由宿主机通过 utmctl 分别在 Linux/Windows/macOS guest 中执行它。
	//
	// 这样可以保证三平台跑的是同一套逻辑，同时避免在 guest 内递归触发 all_platform。
	//
	// 必要前提：
	// - 三台 guest 都已具备 Go 环境
	// - 三台 guest 都有本仓库代码（通过各自 *REPO_DIR 指定）

	t.Run("linux", func(t *testing.T) {
		host := strings.TrimSpace(os.Getenv("TRUSTINSTALL_LINUX_SSH_HOST"))
		if host == "" {
			ip, err := discoverUTMLinuxIPv4("")
			if err != nil {
				t.Fatalf("自动获取 UTM Linux IP 失败: %v", err)
			}
			host = ip
		}
		user := strings.TrimSpace(os.Getenv("TRUSTINSTALL_LINUX_SSH_USER"))
		if user == "" {
			user = "ci"
		}
		port := 22
		if ps := strings.TrimSpace(os.Getenv("TRUSTINSTALL_LINUX_SSH_PORT")); ps != "" {
			if p, err := strconv.Atoi(ps); err == nil && p > 0 && p <= 65535 {
				port = p
			}
		}
		if os.Getenv("TRUSTINSTALL_LINUX_SSH_PASSWORD") == "" {
			t.Setenv("TRUSTINSTALL_LINUX_SSH_PASSWORD", "cipass")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		t.Cleanup(cancel)
		t.Logf("[linux-it] waiting for ssh tcp port %d...", port)
		if err := waitForTCPPort(ctx, host, port, 1*time.Second); err != nil {
			t.Fatalf("Linux guest SSH 端口不可用: %v (host=%s port=%d)", err, host, port)
		}

		// 测试开始就同步代码到 guest（避免 guest 内仓库缺失/旧代码）。
		repoDir := "/home/ci/trustinstall"
		repoRoot, err := findRepoRoot()
		if err != nil {
			t.Fatalf("findRepoRoot err=%v", err)
		}
		ctxUp, cancelUp := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancelUp)
		t.Logf("[linux-it] uploading repo to %s ...", repoDir)
		outU, errU := runWithHeartbeat(t, "upload linux repo", 10*time.Second, func() (string, error) {
			return uploadRepoToLinuxVM(ctxUp, host, port, user, repoDir, repoRoot)
		})
		if errU != nil {
			t.Fatalf("上传仓库到 Linux guest 失败: %v\n%s", errU, outU)
		}

		remoteScript := strings.Join([]string{
			"set -euo pipefail",
			fmtBashExportPATH(),
			"cd " + shellQuote(repoDir),
			`test -f go.mod || (echo "missing go.mod in repoDir" >&2; exit 2)`,
			"export TRUSTINSTALL_INTEGRATION=1",
			`echo "[trustinstall-all-platform] linux repo=` + repoDir + `"`,
			`echo "[trustinstall-all-platform] linux go version:"`,
			`go version`,
			`echo "[trustinstall-all-platform] linux running: go test ./... -tags integration -run TestMITMDynamicLeafCertificate"`,
			`go test ./... -tags integration -run TestMITMDynamicLeafCertificate -count=1 -v`,
		}, "\n")
		cmd := "bash -lc " + shellQuote(remoteScript)

		ctx2, cancel2 := context.WithTimeout(context.Background(), 25*time.Minute)
		t.Cleanup(cancel2)
		out, err := runWithHeartbeat(t, "ssh linux go test", 15*time.Second, func() (string, error) {
			return runSSHCommandGoWithOptions(ctx2, host, port, user, cmd, sshRunOptions{streamOut: true, requestPty: true})
		})
		if err != nil {
			t.Fatalf("UTM Linux 执行失败: %v\n%s", err, out)
		}
		if testing.Verbose() && strings.TrimSpace(out) != "" {
			t.Logf("linux output:\n%s", out)
		}
	})

	t.Run("windows", func(t *testing.T) {
		// 测试开始就同步代码到 guest（避免 guest 内仓库缺失/旧代码）。
		ip, err := discoverUTMIPv4("")
		if err != nil {
			t.Fatalf("自动获取 UTM Windows IP 失败: %v", err)
		}
		endpoint := "http://" + ip + ":5985/wsman"
		repoZipURL, stop, err := startRepoZipServerForWindows(endpoint)
		if err != nil {
			t.Fatalf("启动 repo zip server 失败: %v", err)
		}
		defer stop()

		ps := strings.Join([]string{
			`$ErrorActionPreference = 'Stop'`,
			`$ProgressPreference = 'SilentlyContinue'`,
			`$env:PATH = "C:\go\bin;" + $env:PATH`,
			`$repoDir = 'C:\Users\ci\trustinstall'`,
			`$repoZipUrl = ` + psSingleQuote(repoZipURL),
			`Write-Output ("[trustinstall-all-platform] windows fetching repo zip: " + $repoZipUrl)`,
			`$zipPath = "C:\Temp\trustinstall-src.zip"`,
			`New-Item -ItemType Directory -Force -Path C:\Temp | Out-Null`,
			`if (Test-Path -LiteralPath $repoDir) { Remove-Item -Recurse -Force $repoDir }`,
			`New-Item -ItemType Directory -Force -Path $repoDir | Out-Null`,
			`if (Get-Command curl.exe -ErrorAction SilentlyContinue) {`,
			`  curl.exe -L $repoZipUrl -o $zipPath --max-time 600`,
			`} else {`,
			`  Invoke-WebRequest -UseBasicParsing -Uri $repoZipUrl -OutFile $zipPath`,
			`}`,
			`Expand-Archive -Force -Path $zipPath -DestinationPath $repoDir`,
			`Write-Output ("[trustinstall-all-platform] windows repo=" + $repoDir)`,
			`Set-Location -LiteralPath $repoDir`,
			`if (-not (Test-Path -LiteralPath (Join-Path $PWD 'go.mod'))) { throw "missing go.mod in repoDir=$repoDir" }`,
			`$env:TRUSTINSTALL_INTEGRATION = '1'`,
			`go version`,
			`Write-Output "[trustinstall-all-platform] windows running: go test ./... -tags integration -run TestMITMDynamicLeafCertificate"`,
			`go test ./... -tags integration -run TestMITMDynamicLeafCertificate -count=1 -v`,
		}, "\n")
		encoded := encodePowerShellEncodedCommand(ps)

		out, err := runWithHeartbeat(t, "utmctl exec windows", 15*time.Second, func() (string, error) {
			return utmctlExec("", "powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
		})
		if err != nil {
			t.Fatalf("UTM Windows 执行失败: %v\n%s", err, out)
		}
		if testing.Verbose() && strings.TrimSpace(out) != "" {
			t.Logf("windows output:\n%s", out)
		}
	})

	t.Run("darwin", func(t *testing.T) {
		// macOS guest 使用 SSH 执行（避免 utmctl exec 的 AppleEvent/OSStatus 限制）。
		host := strings.TrimSpace(os.Getenv("TRUSTINSTALL_DARWIN_SSH_HOST"))
		if host == "" {
			ip, err := discoverUTMDarwinIPv4("")
			if err != nil {
				t.Fatalf("自动获取 UTM macOS IP 失败: %v", err)
			}
			host = ip
		}

		user := strings.TrimSpace(os.Getenv("TRUSTINSTALL_DARWIN_SSH_USER"))
		if user == "" {
			user = "ci"
		}
		port := 22
		if ps := strings.TrimSpace(os.Getenv("TRUSTINSTALL_DARWIN_SSH_PORT")); ps != "" {
			if p, err := strconv.Atoi(ps); err == nil && p > 0 && p <= 65535 {
				port = p
			}
		}
		// 复用 ssh_go.go 的密码认证读取逻辑（默认 ci/cipass）。
		if os.Getenv("TRUSTINSTALL_LINUX_SSH_PASSWORD") == "" {
			t.Setenv("TRUSTINSTALL_LINUX_SSH_PASSWORD", "cipass")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		t.Cleanup(cancel)
		t.Logf("[darwin-it] waiting for ssh tcp port %d...", port)
		if err := waitForTCPPort(ctx, host, port, 1*time.Second); err != nil {
			t.Fatalf("macOS guest SSH 端口不可用: %v (host=%s port=%d)", err, host, port)
		}

		ctx2, cancel2 := context.WithTimeout(context.Background(), 25*time.Minute)
		t.Cleanup(cancel2)
		// 测试开始就同步代码到 guest（避免 guest 内仓库缺失/旧代码）。
		repoDir := "/Users/ci/trustinstall"
		repoRoot, err := findRepoRoot()
		if err != nil {
			t.Fatalf("findRepoRoot err=%v", err)
		}
		ctxUp, cancelUp := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancelUp)
		t.Logf("[darwin-it] uploading repo to %s ...", repoDir)
		outU, errU := runWithHeartbeat(t, "upload darwin repo", 10*time.Second, func() (string, error) {
			return uploadRepoToDarwinVM(ctxUp, host, port, user, repoDir, repoRoot)
		})
		if errU != nil {
			t.Fatalf("上传仓库到 macOS guest 失败: %v\n%s", errU, outU)
		}

		remoteScript := strings.Join([]string{
			"set -euo pipefail",
			fmtBashExportPATH(),
			"cd " + shellQuote(repoDir),
			`test -f go.mod || (echo "missing go.mod in repoDir (override via TRUSTINSTALL_DARWIN_REPO_DIR)" >&2; exit 2)`,
			"export TRUSTINSTALL_INTEGRATION=1",
			`echo "[trustinstall-all-platform] darwin repo=` + repoDir + `"`,
			`echo "[trustinstall-all-platform] darwin go version:"`,
			`go version`,
			`echo "[trustinstall-all-platform] darwin running: go test ./... -tags integration -run TestMITMDynamicLeafCertificate"`,
			`go test ./... -tags integration -run TestMITMDynamicLeafCertificate -count=1 -v`,
		}, "\n")
		cmd := "bash -lc " + shellQuote(remoteScript)

		out, err := runWithHeartbeat(t, "ssh darwin go test", 15*time.Second, func() (string, error) {
			return runSSHCommandGoWithOptions(ctx2, host, port, user, cmd, sshRunOptions{streamOut: true, requestPty: true})
		})
		if err != nil {
			t.Fatalf("UTM macOS(SSH) 执行失败: %v\n%s", err, out)
		}
		if testing.Verbose() && strings.TrimSpace(out) != "" {
			t.Logf("darwin output:\n%s", out)
		}
	})
}

func fmtBashExportPATH() string {
	// 在非交互 shell / 不同发行版里 PATH 可能不含 Go；这里做显式兜底。
	return `export PATH="/usr/local/go/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"`
}

func uploadRepoToDarwinVM(ctx context.Context, host string, port int, user, repoDir, localRepoRoot string) (string, error) {
	if strings.TrimSpace(repoDir) == "" || repoDir == "/" {
		return "", fmt.Errorf("非法 repoDir=%q", repoDir)
	}
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
		`if [ ! -f "$tmp/go.mod" ]; then echo "[trustinstall-darwin-it] ERROR: uploaded archive missing go.mod" >&2; exit 4; fi`,
		`rm -rf -- "$repo"`,
		`mkdir -p "$(dirname "$repo")"`,
		`mv "$tmp" "$repo"`,
		`echo "[trustinstall-darwin-it] repo uploaded to $repo"`,
	}, "\n")

	cmd := "bash -lc " + shellQuote(remoteScript)
	return runSSHCommandGoWithOptions(ctx, host, port, user, cmd, sshRunOptions{
		stdin:     pr,
		streamOut: true,
	})
}

func runWithHeartbeat(t *testing.T, label string, interval time.Duration, fn func() (string, error)) (string, error) {
	t.Helper()
	if interval <= 0 {
		interval = 15 * time.Second
	}
	start := time.Now()
	done := make(chan struct{})
	tk := time.NewTicker(interval)
	go func() {
		defer tk.Stop()
		for {
			select {
			case <-done:
				return
			case <-tk.C:
				t.Logf("[progress] %s... elapsed=%s", label, time.Since(start).Round(time.Second))
			}
		}
	}()
	out, err := fn()
	close(done)
	t.Logf("[progress] %s finished elapsed=%s err=%v", label, time.Since(start).Round(time.Second), err)
	return out, err
}

type mitmRecord struct {
	Proto   string
	Method  string
	URL     string
	ReqBody []byte

	Status   string
	RespBody []byte
}

type mitmProxy struct {
	ti      *trustinstall.Client
	maxBody int64

	mu      sync.Mutex
	records []mitmRecord
	gotOne  chan struct{}
}

func newMITMProxy(ti *trustinstall.Client, maxBody int64) *mitmProxy {
	return &mitmProxy{
		ti:      ti,
		maxBody: maxBody,
		gotOne:  make(chan struct{}, 1),
	}
}

func (p *mitmProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT supported in test proxy", http.StatusMethodNotAllowed)
		return
	}
	p.handleConnect(w, r)
}

func (p *mitmProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	_ = clientBuf.Flush()

	_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	host, port := splitHostPortDefault(r.Host, "443")
	serverTLS, err := p.newMITMTLSServer(clientConn, host)
	if err != nil {
		_ = clientConn.Close()
		return
	}

	upstreamTLS, err := p.dialUpstreamTLS(r.Context(), net.JoinHostPort(host, port), host)
	if err != nil {
		_ = serverTLS.Close()
		return
	}

	go func() {
		<-r.Context().Done()
		_ = serverTLS.Close()
		_ = upstreamTLS.Close()
	}()

	p.serveMITMHTTP(serverTLS, upstreamTLS, host)
}

func (p *mitmProxy) newMITMTLSServer(conn net.Conn, host string) (*tls.Conn, error) {
	certPEM, keyPEM, err := p.ti.LeafCertificate(host)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (p *mitmProxy) dialUpstreamTLS(ctx context.Context, addr, serverName string) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: serverName,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (p *mitmProxy) serveMITMHTTP(clientTLS, upstreamTLS net.Conn, host string) {
	clientR := bufio.NewReader(clientTLS)
	upstreamR := bufio.NewReader(upstreamTLS)

	for {
		req, err := http.ReadRequest(clientR)
		if err != nil {
			_ = clientTLS.Close()
			_ = upstreamTLS.Close()
			return
		}

		req.URL.Scheme = "https"
		req.URL.Host = host

		reqBody, _ := readAllLimited(req.Body, p.maxBody)
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
		req.ContentLength = int64(len(reqBody))

		if err := req.Write(upstreamTLS); err != nil {
			_ = clientTLS.Close()
			_ = upstreamTLS.Close()
			return
		}

		resp, err := http.ReadResponse(upstreamR, req)
		if err != nil {
			_ = clientTLS.Close()
			_ = upstreamTLS.Close()
			return
		}

		respBody, _ := readAllLimited(resp.Body, p.maxBody)
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
		resp.ContentLength = int64(len(respBody))

		p.record(mitmRecord{
			Proto:    "HTTPS",
			Method:   req.Method,
			URL:      (&url.URL{Scheme: "https", Host: host, Path: req.URL.Path, RawQuery: req.URL.RawQuery}).String(),
			ReqBody:  reqBody,
			Status:   resp.Status,
			RespBody: respBody,
		})

		if err := resp.Write(clientTLS); err != nil {
			_ = clientTLS.Close()
			_ = upstreamTLS.Close()
			return
		}
	}
}

func (p *mitmProxy) record(r mitmRecord) {
	p.mu.Lock()
	p.records = append(p.records, r)
	p.mu.Unlock()
	select {
	case p.gotOne <- struct{}{}:
	default:
	}
}

func (p *mitmProxy) waitFirstRecord(timeout time.Duration) (mitmRecord, bool) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		p.mu.Lock()
		if len(p.records) > 0 {
			r := p.records[0]
			p.mu.Unlock()
			return r, true
		}
		p.mu.Unlock()

		select {
		case <-p.gotOne:
			// loop and read records
		case <-deadline.C:
			return mitmRecord{}, false
		}
	}
}

func startLocalProxy(t *testing.T, h http.Handler) (*url.URL, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen err=%v", err)
	}

	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ln)
		close(done)
	}()

	u, err := url.Parse("http://" + ln.Addr().String())
	if err != nil {
		_ = srv.Close()
		t.Fatalf("parse proxy url err=%v", err)
	}

	return u, func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
}

func readAllLimited(rc io.ReadCloser, limit int64) ([]byte, error) {
	if rc == nil {
		return nil, nil
	}
	lr := &io.LimitedReader{R: rc, N: limit + 1}
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return b[:limit], nil
	}
	return b, nil
}

func splitHostPortDefault(hostport, defaultPort string) (string, string) {
	h, p, err := net.SplitHostPort(hostport)
	if err == nil {
		return h, p
	}
	return strings.TrimSpace(hostport), defaultPort
}
