//go:build integration || all_platform

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type sshRunOptions struct {
	stdin      io.Reader
	requestPty bool
	streamOut  bool
}

// sshDebugf is a test-only debug hook; keep it nil in normal runs.
var sshDebugf func(format string, args ...any)

func sshLogf(format string, args ...any) {
	if sshDebugf != nil {
		sshDebugf(format, args...)
	}
}

func sshAuthMethods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	// Password auth (optional).
	if pw := os.Getenv("TRUSTINSTALL_LINUX_SSH_PASSWORD"); pw != "" {
		methods = append(methods, ssh.Password(pw))
	}

	// Private key auth from file (optional).
	if keyPath := strings.TrimSpace(os.Getenv("TRUSTINSTALL_LINUX_SSH_KEY")); keyPath != "" {
		b, err := os.ReadFile(filepath.Clean(keyPath))
		if err != nil {
			return nil, fmt.Errorf("读取 SSH 私钥失败: %w", err)
		}
		if pass := os.Getenv("TRUSTINSTALL_LINUX_SSH_KEY_PASSPHRASE"); pass != "" {
			signer, err := ssh.ParsePrivateKeyWithPassphrase(b, []byte(pass))
			if err != nil {
				return nil, fmt.Errorf("解析带口令的 SSH 私钥失败: %w", err)
			}
			methods = append(methods, ssh.PublicKeys(signer))
		} else {
			signer, err := ssh.ParsePrivateKey(b)
			if err != nil {
				return nil, fmt.Errorf("解析 SSH 私钥失败: %w（如有口令请设置 TRUSTINSTALL_LINUX_SSH_KEY_PASSPHRASE）", err)
			}
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}

	// SSH Agent (optional).
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			ag := agent.NewClient(conn)
			methods = append(methods, ssh.PublicKeysCallback(ag.Signers))
		}
	}

	return methods, nil
}

func runSSHCommandGo(ctx context.Context, host string, port int, user string, cmd string) (string, error) {
	return runSSHCommandGoWithOptions(ctx, host, port, user, cmd, sshRunOptions{})
}

func runSSHCommandGoWithStdin(ctx context.Context, host string, port int, user string, cmd string, stdin io.Reader) (string, error) {
	return runSSHCommandGoWithOptions(ctx, host, port, user, cmd, sshRunOptions{stdin: stdin})
}

func runSSHCommandGoWithOptions(ctx context.Context, host string, port int, user string, cmd string, opt sshRunOptions) (string, error) {
	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("empty host")
	}
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("invalid port: %d", port)
	}
	if strings.TrimSpace(user) == "" {
		return "", fmt.Errorf("empty user")
	}

	methods, err := sshAuthMethods()
	if err != nil {
		return "", err
	}
	if len(methods) == 0 {
		return "", fmt.Errorf("未配置 SSH 认证方式：请设置 TRUSTINSTALL_LINUX_SSH_KEY 或 TRUSTINSTALL_LINUX_SSH_PASSWORD，或确保 SSH agent 可用（SSH_AUTH_SOCK）")
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// ssh.Dial 不支持 context，先用 net.Dialer 建连接再握手。
	sshLogf("[ssh] dial tcp: addr=%s", addr)
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		sshLogf("[ssh] dial failed: addr=%s err=%v", addr, err)
		return "", err
	}
	// Make command execution cancelable: if ctx expires, closing the underlying net.Conn will unblock reads/writes.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
	defer close(done)
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}

	sshLogf("[ssh] handshake start: addr=%s user=%s", addr, user)
	conn, chans, reqs, err := ssh.NewClientConn(c, addr, cfg)
	if err != nil {
		_ = c.Close()
		sshLogf("[ssh] handshake failed: addr=%s err=%v", addr, err)
		return "", err
	}
	sshLogf("[ssh] handshake ok: addr=%s", addr)
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	sshLogf("[ssh] new session: addr=%s", addr)
	sess, err := client.NewSession()
	if err != nil {
		sshLogf("[ssh] NewSession failed: addr=%s err=%v", addr, err)
		return "", err
	}
	defer sess.Close()

	var outBuf bytes.Buffer
	if opt.streamOut && sshDebugf != nil {
		w := newLineLogWriter(&outBuf, func(line string) {
			sshLogf("[ssh-out] %s", line)
		})
		sess.Stdout = w
		sess.Stderr = w
	} else {
		sess.Stdout = &outBuf
		sess.Stderr = &outBuf
	}

	if opt.requestPty {
		sshLogf("[ssh] request pty: addr=%s", addr)
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := sess.RequestPty("xterm", 80, 40, modes); err != nil {
			sshLogf("[ssh] RequestPty failed: addr=%s err=%v", addr, err)
			return "", fmt.Errorf("RequestPty 失败: %w", err)
		}
	}
	if opt.stdin != nil {
		sess.Stdin = opt.stdin
	}
	sshLogf("[ssh] run cmd: addr=%s len=%d", addr, len(cmd))
	err = sess.Run(cmd)
	out := outBuf.String()
	sshLogf("[ssh] cmd done: addr=%s err=%v outLen=%d", addr, err, len(out))
	return out, err
}

type lineLogWriter struct {
	mu     sync.Mutex
	buf    []byte
	dst    io.Writer
	onLine func(string)
}

func newLineLogWriter(dst io.Writer, onLine func(string)) *lineLogWriter {
	return &lineLogWriter{
		dst:    dst,
		onLine: onLine,
	}
}

func (w *lineLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.dst != nil {
		_, _ = w.dst.Write(p)
	}
	w.buf = append(w.buf, p...)

	flush := func(line []byte) {
		s := strings.TrimRight(string(line), "\r\n")
		if strings.TrimSpace(s) == "" {
			return
		}
		if w.onLine != nil {
			w.onLine(s)
		}
	}

	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := w.buf[:i+1]
		w.buf = w.buf[i+1:]
		flush(line)
	}
	return len(p), nil
}

func isSSHAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unable to authenticate") {
		return true
	}
	if strings.Contains(msg, "permission denied") {
		return true
	}
	return false
}
