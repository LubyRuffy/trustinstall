package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LubyRuffy/trustinstall"
)

func main() {
	var (
		listenAddr  = flag.String("listen", "127.0.0.1:8080", "监听地址")
		caDir       = flag.String("ca-dir", defaultCADir(), "CA 文件目录")
		caName      = flag.String("ca-name", "trustinstall-ca", "CA 文件基名（不含后缀）")
		caCN        = flag.String("ca-common-name", "trustinstall-ca", "CA 证书 CommonName（生成用；若文件已存在则以文件内证书为准）")
		deleteSame  = flag.Bool("delete-same", true, "系统中存在多个同名证书时，是否删除与本地证书不一致的那些")
		maxBodySize = flag.Int64("max-body-bytes", 1<<20, "打印 body 的最大字节数（超过会截断）")
	)
	flag.Parse()

	ti, err := trustinstall.New(trustinstall.Options{
		Dir:          *caDir,
		FileBaseName: *caName,
		CommonName:   *caCN,
		DeleteSame:   deleteSame,
	})
	if err != nil {
		log.Fatalf("trustinstall.New 失败: %v", err)
	}
	if err := ti.InstallCA(); err != nil {
		log.Fatalf("InstallCA 失败: %v", err)
	}

	p := &proxy{
		ti:          ti,
		maxBodySize: *maxBodySize,
	}

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("proxy listen on %s", *listenAddr)
	log.Printf("CA: %s / %s.crt", ti.Dir(), ti.FileBaseName())
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

type proxy struct {
	ti          *trustinstall.Client
	maxBodySize int64
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// For plain HTTP proxy requests, URL is absolute-form (e.g. http://host/path).
	reqCopy := r.Clone(r.Context())
	body, _ := readAllLimited(reqCopy.Body, p.maxBodySize)
	_ = reqCopy.Body.Close()
	reqCopy.Body = io.NopCloser(bytes.NewReader(body))
	reqCopy.ContentLength = int64(len(body))

	p.printRequest("HTTP", reqCopy, body)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = false

	resp, err := transport.RoundTrip(reqCopy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := readAllLimited(resp.Body, p.maxBodySize)
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	resp.ContentLength = int64(len(respBody))

	p.printResponse("HTTP", reqCopy, resp, respBody)

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

func (p *proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
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

	// We take over the connection from net/http.
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

func (p *proxy) newMITMTLSServer(conn net.Conn, host string) (*tls.Conn, error) {
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
	})
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (p *proxy) dialUpstreamTLS(ctx context.Context, addr, serverName string) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: serverName,
		NextProtos: []string{"http/1.1"},
		// RootCAs 为 nil 时使用系统根证书，适合做上游校验。
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (p *proxy) serveMITMHTTP(clientTLS, upstreamTLS net.Conn, host string) {
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

		reqBody, _ := readAllLimited(req.Body, p.maxBodySize)
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
		req.ContentLength = int64(len(reqBody))

		p.printRequest("HTTPS", req, reqBody)

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

		respBody, _ := readAllLimited(resp.Body, p.maxBodySize)
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
		resp.ContentLength = int64(len(respBody))

		p.printResponse("HTTPS", req, resp, respBody)

		if err := resp.Write(clientTLS); err != nil {
			_ = clientTLS.Close()
			_ = upstreamTLS.Close()
			return
		}
	}
}

func (p *proxy) printRequest(proto string, r *http.Request, body []byte) {
	// Avoid dumping raw Authorization cookies etc for safety; keep minimal.
	dump, _ := httputil.DumpRequest(r, false)
	fmt.Printf("\n==== %s REQUEST ====\n%s", proto, string(dump))
	if len(body) > 0 {
		fmt.Printf("\n---- body (%d bytes) ----\n%s\n", len(body), printable(body))
	}
}

func (p *proxy) printResponse(proto string, req *http.Request, resp *http.Response, body []byte) {
	dump, _ := httputil.DumpResponse(resp, false)
	fmt.Printf("\n==== %s RESPONSE (%s %s) ====\n%s", proto, req.Method, req.URL.String(), string(dump))
	if len(body) > 0 {
		fmt.Printf("\n---- body (%d bytes) ----\n%s\n", len(body), printable(body))
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

func printable(b []byte) string {
	s := string(b)
	// Keep it readable for most APIs; binary still passes through.
	return strings.ReplaceAll(s, "\r\n", "\n")
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func splitHostPortDefault(hostport, defaultPort string) (string, string) {
	h, p, err := net.SplitHostPort(hostport)
	if err == nil {
		return h, p
	}
	return hostport, defaultPort
}

func defaultCADir() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ".trustinstall"
	}
	return filepath.Join(home, ".trustinstall")
}
