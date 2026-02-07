package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

type Options struct {
	// Addr is the preferred listen address, e.g. "127.0.0.1:34115".
	Addr string
	// FallbackPorts is the number of extra ports to try, e.g. 10 means [port, port+10].
	FallbackPorts int

	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

// Start starts the local API server in a goroutine and returns the server.
// It will try Addr first and then fall back to sequential ports if the port is already in use.
func Start(opts Options) (*http.Server, error) {
	if opts.Addr == "" {
		return nil, fmt.Errorf("api: Addr 不能为空")
	}

	host, portStr, err := net.SplitHostPort(opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("api: Addr 非法: %w", err)
	}
	basePort, err := strconv.Atoi(portStr)
	if err != nil || basePort <= 0 || basePort > 65535 {
		return nil, fmt.Errorf("api: 端口非法: %q", portStr)
	}

	handler := newRouter(defaultInstaller())

	tryN := opts.FallbackPorts + 1
	if tryN < 1 {
		tryN = 1
	}

	var lastErr error
	for i := 0; i < tryN; i++ {
		addr := net.JoinHostPort(host, strconv.Itoa(basePort+i))
		ln, listenErr := net.Listen("tcp", addr)
		if listenErr != nil {
			lastErr = listenErr
			continue
		}

		srv := &http.Server{
			Addr:         addr,
			Handler:      handler,
			ReadTimeout:  opts.ReadTimeout,
			WriteTimeout: opts.WriteTimeout,
		}

		go func() {
			_ = srv.Serve(ln)
		}()

		return srv, nil
	}

	if lastErr != nil {
		// Normalize common "port already in use" cause for easier debugging.
		if errors.Is(lastErr, net.ErrClosed) {
			return nil, fmt.Errorf("api: listen 失败: %w", lastErr)
		}
		return nil, fmt.Errorf("api: listen 失败: %w", lastErr)
	}
	return nil, fmt.Errorf("api: listen 失败: 未知错误")
}
