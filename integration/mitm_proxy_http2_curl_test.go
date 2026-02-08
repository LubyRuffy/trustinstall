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
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LubyRuffy/trustinstall"
	"golang.org/x/net/http2"
)

func TestMITMProxy_CurlHTTP2AndHTTP11(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skipf("curl not found: %v", err)
	}

	tmp := t.TempDir()
	caCertPath, _, caCert, err := trustinstall.EnsureCAFiles(tmp, "mitm-ca", "mitm-ca")
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

	originAddr, closeOrigin := startLocalHTTP2Origin(t, ti)
	t.Cleanup(closeOrigin)

	p := newH2MITMProxy(ti, caCert, originAddr, 1<<20)
	proxyURL, closeProxy := startLocalProxy(t, p)
	t.Cleanup(closeProxy)
	if testing.Verbose() {
		t.Logf("ca=%s origin=%s proxy=%s", caCertPath, originAddr, proxyURL.String())
	}

	// 1) 强制 HTTP/2
	out, curlLog := runCurlViaProxy(t, proxyURL.String(), caCertPath, "https://csdn.com/", "--http2")
	if testing.Verbose() {
		t.Logf("curl --http2 stdout:\n%s", tailString(out, 2000))
		t.Logf("curl --http2 stderr:\n%s", tailString(curlLog, 4000))
	}
	if !strings.Contains(out, "origin proto=HTTP/2.0") {
		t.Fatalf("http2 curl body mismatch: %q", out)
	}
	rec, ok := p.waitNRecords(1, 10*time.Second)
	if !ok {
		t.Fatalf("no proxy record for http2 request")
	}
	if testing.Verbose() {
		t.Logf("proxy record http2: client=%s upstream=%s method=%s status=%s", rec.ClientProto, rec.UpstreamProto, rec.Method, rec.Status)
	}
	if rec.ClientProto != "HTTP/2.0" || rec.UpstreamProto != "HTTP/2.0" {
		t.Fatalf("http2 proto mismatch: client=%s upstream=%s", rec.ClientProto, rec.UpstreamProto)
	}

	// 2) 强制 HTTP/1.1
	p.resetRecords()
	out, curlLog = runCurlViaProxy(t, proxyURL.String(), caCertPath, "https://csdn.com/", "--http1.1")
	if testing.Verbose() {
		t.Logf("curl --http1.1 stdout:\n%s", tailString(out, 2000))
		t.Logf("curl --http1.1 stderr:\n%s", tailString(curlLog, 4000))
	}
	if !strings.Contains(out, "origin proto=HTTP/1.1") {
		t.Fatalf("http1.1 curl body mismatch: %q", out)
	}
	rec, ok = p.waitNRecords(1, 10*time.Second)
	if !ok {
		t.Fatalf("no proxy record for http1.1 request")
	}
	if testing.Verbose() {
		t.Logf("proxy record http1.1: client=%s upstream=%s method=%s status=%s", rec.ClientProto, rec.UpstreamProto, rec.Method, rec.Status)
	}
	if rec.ClientProto != "HTTP/1.1" || rec.UpstreamProto != "HTTP/1.1" {
		t.Fatalf("http1.1 proto mismatch: client=%s upstream=%s", rec.ClientProto, rec.UpstreamProto)
	}
}

func runCurlViaProxy(t *testing.T, proxyURL, caCertPath, targetURL string, protoFlag string) (string, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Body to stdout; -v to stderr. We capture both to make debugging easier on failure,
	// and return stdout as the "content" check target.
	cmd := exec.CommandContext(ctx, "curl",
		"-sS",
		"-v",
		"--max-time", "15",
		"--proxy", proxyURL,
		"--cacert", caCertPath,
		protoFlag,
		targetURL,
	)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()
	if err != nil {
		t.Fatalf("curl failed: %v\nstderr:\n%s\nstdout:\n%s", err, stderrBuf.String(), stdoutBuf.String())
	}
	if strings.TrimSpace(stdoutBuf.String()) == "" {
		t.Fatalf("curl empty stdout\nstderr:\n%s", stderrBuf.String())
	}
	return stdoutBuf.String(), stderrBuf.String()
}

func startLocalHTTP2Origin(t *testing.T, ti *trustinstall.Client) (addr string, closeFn func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen err=%v", err)
	}

	certPEM, keyPEM, err := ti.LeafCertificate("csdn.com")
	if err != nil {
		_ = ln.Close()
		t.Fatalf("LeafCertificate err=%v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("X509KeyPair err=%v", err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("X-Origin-Proto", r.Proto)
			_, _ = io.WriteString(w, fmt.Sprintf("origin proto=%s\n", r.Proto))
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		_ = ln.Close()
		t.Fatalf("ConfigureServer err=%v", err)
	}

	tlsLn := tls.NewListener(ln, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})

	done := make(chan struct{})
	go func() {
		_ = srv.Serve(tlsLn)
		close(done)
	}()

	return ln.Addr().String(), func() {
		_ = srv.Close()
		_ = ln.Close()
		<-done
	}
}

type h2MitmRecord struct {
	ClientProto   string
	UpstreamProto string
	Method        string
	Status        string
}

type h2MITMProxy struct {
	ti            *trustinstall.Client
	maxBody       int64
	originAddr    string
	upstreamRoots *x509.CertPool

	mu      sync.Mutex
	records []h2MitmRecord
	gotOne  chan struct{}
}

func newH2MITMProxy(ti *trustinstall.Client, caCert *x509.Certificate, originAddr string, maxBody int64) *h2MITMProxy {
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &h2MITMProxy{
		ti:            ti,
		maxBody:       maxBody,
		originAddr:    originAddr,
		upstreamRoots: pool,
		gotOne:        make(chan struct{}, 1),
	}
}

func (p *h2MITMProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT supported in test proxy", http.StatusMethodNotAllowed)
		return
	}
	p.handleConnect(w, r)
}

func (p *h2MITMProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
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
	upstreamAddr := net.JoinHostPort(host, port)
	dialAddr := p.mapUpstreamAddr(upstreamAddr)

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	serverTLS, negotiatedALPN, err := p.newMITMTLSServerWithALPNProbe(ctx, clientConn, dialAddr, host)
	if err != nil {
		_ = clientConn.Close()
		return
	}

	go func() {
		<-r.Context().Done()
		_ = serverTLS.Close()
	}()

	switch negotiatedALPN {
	case "h2":
		p.serveMITMHTTP2(ctx, serverTLS, dialAddr, host)
	default:
		upstreamTLS, err := p.dialUpstreamTLSWithALPN(ctx, dialAddr, host, negotiatedALPN)
		if err != nil {
			_ = serverTLS.Close()
			return
		}
		go func() {
			<-r.Context().Done()
			_ = upstreamTLS.Close()
		}()
		p.serveMITMHTTP11(serverTLS, upstreamTLS, host)
	}
}

func (p *h2MITMProxy) mapUpstreamAddr(addr string) string {
	if addr == "csdn.com:443" {
		return p.originAddr
	}
	return addr
}

func (p *h2MITMProxy) newMITMTLSServerWithALPNProbe(ctx context.Context, conn net.Conn, dialAddr, upstreamServerName string) (*tls.Conn, string, error) {
	certPEM, keyPEM, err := p.ti.LeafCertificate(upstreamServerName)
	if err != nil {
		return nil, "", err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, "", err
	}

	var negotiated string
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			clientProtos := filterHTTPALPNs(hello.SupportedProtos)
			upProto, err := p.probeUpstreamALPN(ctx, dialAddr, upstreamServerName, clientProtos)
			if err != nil {
				return nil, err
			}
			negotiated = upProto
			return &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{upProto},
			}, nil
		},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, "", err
	}
	if negotiated == "" {
		negotiated = normalizeALPN(tlsConn.ConnectionState().NegotiatedProtocol)
	}
	return tlsConn, negotiated, nil
}

func (p *h2MITMProxy) probeUpstreamALPN(ctx context.Context, dialAddr, serverName string, clientProtos []string) (string, error) {
	raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return "", err
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: serverName,
		NextProtos: clientProtos,
		MinVersion: tls.VersionTLS12,
		RootCAs:    p.upstreamRoots,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return "", err
	}
	neg := normalizeALPN(tlsConn.ConnectionState().NegotiatedProtocol)
	_ = tlsConn.Close()
	return neg, nil
}

func (p *h2MITMProxy) dialUpstreamTLSWithALPN(ctx context.Context, dialAddr, serverName, alpn string) (*tls.Conn, error) {
	raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: serverName,
		NextProtos: []string{alpn},
		MinVersion: tls.VersionTLS12,
		RootCAs:    p.upstreamRoots,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (p *h2MITMProxy) serveMITMHTTP11(clientTLS, upstreamTLS net.Conn, host string) {
	// We use a small, explicit HTTP/1.1 loop here to keep the integration test focused.
	clientR := bufioNewReader(clientTLS)
	upstreamR := bufioNewReader(upstreamTLS)

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

		p.record(h2MitmRecord{
			ClientProto:   req.Proto,
			UpstreamProto: resp.Proto,
			Method:        req.Method,
			Status:        resp.Status,
		})

		resp.Body = io.NopCloser(bytes.NewReader(respBody))
		resp.ContentLength = int64(len(respBody))
		if err := resp.Write(clientTLS); err != nil {
			_ = clientTLS.Close()
			_ = upstreamTLS.Close()
			return
		}
	}
}

func (p *h2MITMProxy) serveMITMHTTP2(ctx context.Context, clientTLS *tls.Conn, dialAddr, upstreamServerName string) {
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: upstreamServerName,
			NextProtos: []string{"h2"},
			MinVersion: tls.VersionTLS12,
			RootCAs:    p.upstreamRoots,
		},
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, dialAddr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = tlsConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, _ := readAllLimited(r.Body, p.maxBody)
		_ = r.Body.Close()

		outReq := r.Clone(r.Context())
		outReq.RequestURI = ""
		outReq.URL.Scheme = "https"
		outReq.URL.Host = upstreamServerName
		outReq.Host = upstreamServerName
		outReq.Body = io.NopCloser(bytes.NewReader(reqBody))
		outReq.ContentLength = int64(len(reqBody))

		resp, err := client.Do(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		respBody, _ := readAllLimited(resp.Body, p.maxBody)
		p.record(h2MitmRecord{
			ClientProto:   r.Proto,
			UpstreamProto: resp.Proto,
			Method:        r.Method,
			Status:        resp.Status,
		})

		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
	})

	var s http2.Server
	s.ServeConn(clientTLS, &http2.ServeConnOpts{Handler: handler})
}

func (p *h2MITMProxy) record(r h2MitmRecord) {
	p.mu.Lock()
	p.records = append(p.records, r)
	p.mu.Unlock()
	select {
	case p.gotOne <- struct{}{}:
	default:
	}
}

func (p *h2MITMProxy) resetRecords() {
	p.mu.Lock()
	p.records = nil
	p.mu.Unlock()
}

func (p *h2MITMProxy) waitNRecords(n int, timeout time.Duration) (h2MitmRecord, bool) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		p.mu.Lock()
		if len(p.records) >= n {
			r := p.records[n-1]
			p.mu.Unlock()
			return r, true
		}
		p.mu.Unlock()

		select {
		case <-p.gotOne:
		case <-deadline.C:
			return h2MitmRecord{}, false
		}
	}
}

// Minimal helpers duplicated here to keep the test self-contained and avoid importing cmd/proxy (main).
func normalizeALPN(p string) string {
	if strings.TrimSpace(p) == "" {
		return "http/1.1"
	}
	return p
}

func filterHTTPALPNs(in []string) []string {
	var out []string
	seen := make(map[string]struct{}, 2)
	for _, p := range in {
		if p != "h2" && p != "http/1.1" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return []string{"http/1.1"}
	}
	return out
}

func bufioNewReader(c net.Conn) *bufio.Reader {
	// bufio is only used in the HTTP/1.1 path.
	return bufio.NewReader(c)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func tailString(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}
