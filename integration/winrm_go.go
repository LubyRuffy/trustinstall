//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/masterzen/winrm"
)

type winrmResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

func runWinRMEncodedPowerShell(ctx context.Context, endpointURL, user, password, encodedCommand string) (winrmResult, error) {
	u, err := url.Parse(strings.TrimSpace(endpointURL))
	if err != nil {
		return winrmResult{}, fmt.Errorf("解析 endpoint 失败: %w", err)
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return winrmResult{}, fmt.Errorf("endpoint 缺少 host: %q", endpointURL)
	}
	port := 5985
	if p := strings.TrimSpace(u.Port()); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 {
			return winrmResult{}, fmt.Errorf("endpoint port 非法: %q", p)
		}
		port = n
	}
	https := strings.EqualFold(u.Scheme, "https")
	if u.Scheme != "http" && u.Scheme != "https" {
		return winrmResult{}, fmt.Errorf("endpoint scheme 非法: %q", u.Scheme)
	}

	params := winrm.NewParameters("PT120S", "en-US", 153600)
	// 我们的 Windows CI/UTM 环境通常只开了 Negotiate/NTLM（且往往要求 message encryption）。
	// 这里优先使用 winrm.Encryption("ntlm")，行为更接近 pywinrm。
	params.TransportDecorator = func() winrm.Transporter {
		enc, err := winrm.NewEncryption("ntlm")
		if err == nil && enc != nil {
			return enc
		}
		// 兜底到传统 NTLM transport（部分环境不需要 encryption 也能用）。
		return winrm.NewClientNTLMWithDial(params.Dial)
	}
	// 在 CI 环境上偶发慢，放宽超时。
	endpoint := winrm.NewEndpoint(host, port, https, true, nil, nil, nil, 3*time.Minute)
	client, err := winrm.NewClientWithParameters(endpoint, user, password, params)
	if err != nil {
		return winrmResult{}, fmt.Errorf("创建 WinRM client 失败: %w", err)
	}

	cmd := "powershell -NoProfile -NonInteractive -EncodedCommand " + encodedCommand
	var stdout, stderr bytes.Buffer
	exit, err := client.RunWithContext(ctx, cmd, &stdout, &stderr)
	res := winrmResult{
		ExitCode: exit,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}
	if err != nil {
		return res, err
	}
	if exit != 0 {
		return res, fmt.Errorf("exit status %d", exit)
	}
	return res, nil
}
