package webview2bridge

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// LocalProxy là HTTP CONNECT proxy chạy in-process. Hỗ trợ HTTPS (CONNECT)
// và HTTP plain. SetUpstream có thể đổi upstream proxy mid-flight, các
// CONNECT đang sống vẫn dùng upstream cũ; CONNECT mới dùng upstream mới.
//
// Lý do: WebView2 (Edge) không xử lý ổn định --proxy-server với credentials
// embedded URL, và pkg/edge của wailsapp/go-webview2 chưa expose
// ICoreWebView2_10.BasicAuthenticationRequested. Chạy local proxy no-auth
// trên 127.0.0.1, forward + tự inject Proxy-Authorization là cách robust nhất.
type LocalProxy struct {
	listener net.Listener

	mu       sync.RWMutex
	upstream *url.URL
}

func NewLocalProxy() (*LocalProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	p := &LocalProxy{listener: ln}
	go p.serve()
	return p, nil
}

func (p *LocalProxy) Addr() string { return p.listener.Addr().String() }

func (p *LocalProxy) Close() error { return p.listener.Close() }

// SetUpstream thay đổi upstream proxy. Truyền chuỗi rỗng để xóa.
func (p *LocalProxy) SetUpstream(rawURL string) error {
	if rawURL == "" {
		p.mu.Lock()
		p.upstream = nil
		p.mu.Unlock()
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse upstream: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported upstream scheme: %s", u.Scheme)
	}
	p.mu.Lock()
	p.upstream = u
	p.mu.Unlock()
	return nil
}

func (p *LocalProxy) currentUpstream() *url.URL {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.upstream
}

func (p *LocalProxy) serve() {
	for {
		c, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *LocalProxy) handle(client net.Conn) {
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Minute))

	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	upstream := p.currentUpstream()
	if upstream == nil {
		writeStatus(client, 502, "no upstream proxy configured")
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(client, br, req, upstream)
		return
	}
	p.handlePlain(client, req, upstream)
}

func (p *LocalProxy) handleConnect(client net.Conn, br *bufio.Reader, req *http.Request, upstream *url.URL) {
	upConn, err := dialUpstream(upstream)
	if err != nil {
		writeStatus(client, 502, "upstream dial: "+err.Error())
		return
	}
	defer upConn.Close()

	authHeader := basicAuthHeader(upstream)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", req.URL.Host, req.URL.Host)
	if authHeader != "" {
		connectReq += "Proxy-Authorization: " + authHeader + "\r\n"
	}
	connectReq += "\r\n"

	if _, err := upConn.Write([]byte(connectReq)); err != nil {
		writeStatus(client, 502, "upstream write: "+err.Error())
		return
	}

	upBr := bufio.NewReader(upConn)
	resp, err := http.ReadResponse(upBr, req)
	if err != nil {
		writeStatus(client, 502, "upstream read: "+err.Error())
		return
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		writeStatus(client, resp.StatusCode, fmt.Sprintf("upstream %d: %s", resp.StatusCode, string(body)))
		return
	}
	_ = resp.Body.Close()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	bidiPipe(client, br, upConn, upBr)
}

func (p *LocalProxy) handlePlain(client net.Conn, req *http.Request, upstream *url.URL) {
	upConn, err := dialUpstream(upstream)
	if err != nil {
		writeStatus(client, 502, "upstream dial: "+err.Error())
		return
	}
	defer upConn.Close()

	authHeader := basicAuthHeader(upstream)
	req.Header.Del("Proxy-Authorization")
	if authHeader != "" {
		req.Header.Set("Proxy-Authorization", authHeader)
	}

	if err := req.WriteProxy(upConn); err != nil {
		writeStatus(client, 502, "write upstream: "+err.Error())
		return
	}

	upBr := bufio.NewReader(upConn)
	resp, err := http.ReadResponse(upBr, req)
	if err != nil {
		writeStatus(client, 502, "read upstream: "+err.Error())
		return
	}
	defer resp.Body.Close()

	_ = resp.Write(client)
}

func dialUpstream(u *url.URL) (net.Conn, error) {
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	return dialer.DialContext(context.Background(), "tcp", host)
}

func basicAuthHeader(u *url.URL) string {
	if u == nil || u.User == nil {
		return ""
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" && pass == "" {
		return ""
	}
	creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	return "Basic " + creds
}

func writeStatus(w io.Writer, code int, body string) {
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

func bidiPipe(c1 net.Conn, br1 *bufio.Reader, c2 net.Conn, br2 *bufio.Reader) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = copyBuffered(c2, br1)
		if tc, ok := c2.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = copyBuffered(c1, br2)
		if tc, ok := c1.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func copyBuffered(dst io.Writer, src *bufio.Reader) (int64, error) {
	if n := src.Buffered(); n > 0 {
		buf, _ := src.Peek(n)
		if _, err := dst.Write(buf); err != nil {
			return 0, err
		}
		_, _ = src.Discard(n)
	}
	return io.Copy(dst, src)
}
