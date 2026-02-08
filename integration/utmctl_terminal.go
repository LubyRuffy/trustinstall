//go:build integration || all_platform

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func isUTMCtlAutomationDenied(output string) bool {
	s := strings.ToLower(output)
	if strings.Contains(s, "osstatus error -1743") {
		return true
	}
	if strings.Contains(s, "utmctl does not work from ssh sessions") {
		return true
	}
	return false
}

func isUTMCtlEventError(output string) bool {
	s := strings.ToLower(output)
	// utmctl may print an AppleEvent error but still exit 0, which would otherwise be treated as success.
	// Example:
	// Error from event: The operation couldn’t be completed. (OSStatus error -10004.)
	if strings.Contains(s, "error from event:") && strings.Contains(s, "osstatus error") {
		return true
	}
	// Be conservative: any OSStatus error line indicates the command didn't actually execute.
	if strings.Contains(s, "osstatus error -") {
		return true
	}
	return false
}

func shellQuote(s string) string {
	// Safe for zsh/bash: ' -> '"'"'
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func runUTMCtl(args []string, timeout time.Duration) ([]byte, error) {
	utmctl := utmctlPath()

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, utmctl, args...)
	out, err := cmd.CombinedOutput()

	if err == nil && ctx.Err() == nil && !isUTMCtlAutomationDenied(string(out)) {
		return out, nil
	}

	// If direct execution times out, treat it like "cannot talk to UI session" and retry via Terminal.
	if ctx.Err() == context.DeadlineExceeded {
		out2, err2 := runUTMCtlViaTerminal(utmctl, args, timeout)
		if err2 == nil {
			return out2, nil
		}
		return out, fmt.Errorf("utmctl 运行超时: %w; Terminal fallback 失败: %v", err, err2)
	}

	if !isUTMCtlAutomationDenied(string(out)) {
		// Non-automation errors: keep original behavior.
		return out, err
	}

	// Fallback: run via Terminal to inherit GUI/session permissions (TCC/Apple Events/Files & Folders).
	out2, err2 := runUTMCtlViaTerminal(utmctl, args, timeout)
	if err2 == nil {
		return out2, nil
	}
	// Prefer the original utmctl output (it contains the OSStatus -1743 hint).
	if err == nil {
		err = fmt.Errorf("utmctl automation denied")
	}
	return out, fmt.Errorf("utmctl 运行失败（疑似无 UI/Automation 权限）: %w; Terminal fallback 失败: %v", err, err2)
}

func runUTMCtlViaTerminal(utmctl string, args []string, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	timeoutSecs := int(timeout.Round(time.Second).Seconds())
	if timeoutSecs <= 0 {
		timeoutSecs = 1
	}

	tmpDir, err := os.MkdirTemp("", "trustinstall-utmctl-terminal-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	scriptPath := filepath.Join(tmpDir, "utmctl.command")
	stdoutPath := filepath.Join(tmpDir, "stdout.txt")
	stderrPath := filepath.Join(tmpDir, "stderr.txt")
	codePath := filepath.Join(tmpDir, "code.txt")

	var parts []string
	parts = append(parts, shellQuote(utmctl))
	for _, a := range args {
		parts = append(parts, shellQuote(a))
	}
	cmdline := strings.Join(parts, " ")

	script := strings.Join([]string{
		"#!/bin/zsh",
		"set -uo pipefail",
		"timeout_secs=" + strconv.Itoa(timeoutSecs),
		"out=" + shellQuote(stdoutPath),
		"err=" + shellQuote(stderrPath),
		"code=" + shellQuote(codePath),
		// Always capture exit code. Use a watchdog to avoid leaking hung utmctl processes
		// (e.g. waiting for a TCC prompt that cannot be acknowledged in CI).
		cmdline + ` >"$out" 2>"$err" &`,
		`pid=$!`,
		`(`,
		`  sleep "$timeout_secs"`,
		`  kill -TERM "$pid" 2>/dev/null || true`,
		`  sleep 2`,
		`  kill -KILL "$pid" 2>/dev/null || true`,
		`) &`,
		`watchdog=$!`,
		`wait "$pid"`,
		`ec=$?`,
		`kill "$watchdog" 2>/dev/null || true`,
		`echo "$ec" >"$code"`,
		"exit 0",
		"",
	}, "\n")

	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		return nil, err
	}

	// Use -g/-j to avoid stealing focus if possible; fall back to plain open.
	openArgs := []string{"-gj", "-a", "Terminal", scriptPath}
	if err := exec.Command("open", openArgs...).Run(); err != nil {
		openArgs = []string{"-g", "-a", "Terminal", scriptPath}
		if err2 := exec.Command("open", openArgs...).Run(); err2 != nil {
			openArgs = []string{"-a", "Terminal", scriptPath}
			if err3 := exec.Command("open", openArgs...).Run(); err3 != nil {
				return nil, fmt.Errorf("open Terminal 失败: %w", err3)
			}
		}
	}

	// Script has an internal watchdog that may take a couple seconds to SIGKILL + flush files.
	deadline := time.Now().Add(timeout + 5*time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(codePath)
		if err == nil {
			s := strings.TrimSpace(string(b))
			if s != "" {
				ec, _ := strconv.Atoi(s)
				stdout, _ := os.ReadFile(stdoutPath)
				stderr, _ := os.ReadFile(stderrPath)
				combined := append(stdout, stderr...)
				if ec != 0 {
					return combined, fmt.Errorf("exit status %d", ec)
				}
				return combined, nil
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return nil, fmt.Errorf("等待 Terminal 执行 utmctl 超时（%s）", timeout)
}
