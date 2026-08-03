package webview2bridge

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
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
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" {
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
	if upstream.Scheme == "socks5" {
		// SOCKS5's CONNECT already tunnels straight to the real target — no
		// separate HTTP CONNECT request to write, unlike the http/https
		// upstream case below.
		upConn, err := dialSOCKS5(upstream, req.URL.Host)
		if err != nil {
			writeStatus(client, 502, "socks5 dial: "+err.Error())
			return
		}
		defer upConn.Close()
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		bidiPipe(client, br, upConn, bufio.NewReader(upConn))
		return
	}

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
	if upstream.Scheme == "socks5" {
		// A SOCKS5 dialer connects straight to the origin, so this writes a
		// direct-to-origin request (Write), not a forward-proxy one
		// (WriteProxy) — there's no intermediate HTTP proxy to address it to.
		upConn, err := dialSOCKS5(upstream, req.URL.Host)
		if err != nil {
			writeStatus(client, 502, "socks5 dial: "+err.Error())
			return
		}
		defer upConn.Close()

		req.Header.Del("Proxy-Authorization")
		if err := req.Write(upConn); err != nil {
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
		return
	}

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

// dialSOCKS5 opens a connection to targetHostPort through the SOCKS5
// server described by upstream (host + optional embedded user:pass),
// performing the full SOCKS5 handshake. The returned conn is already a
// direct tunnel to the target — no further proxy protocol to speak.
func dialSOCKS5(upstream *url.URL, targetHostPort string) (net.Conn, error) {
	var auth *proxy.Auth
	if upstream.User != nil {
		user := upstream.User.Username()
		pass, _ := upstream.User.Password()
		auth = &proxy.Auth{User: user, Password: pass}
	}
	dialer, err := proxy.SOCKS5("tcp", upstream.Host, auth, &net.Dialer{Timeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", targetHostPort)
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
	if u.Scheme == "https" {
		// scheme=https means the proxy *itself* is only reachable over TLS
		// (e.g. PIA's proxy on :443) — the CONNECT/plain-HTTP request below
		// then rides inside that TLS session. A plain TCP dial here would
		// hand the proxy raw HTTP bytes on a TLS-only port and just hang or
		// get dropped, since there'd be no handshake to unwrap them.
		hostname := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			hostname = h
		}
		return tls.DialWithDialer(dialer, "tcp", host, &tls.Config{ServerName: hostname})
	}
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
