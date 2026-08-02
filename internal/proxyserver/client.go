// Package proxyserver is a lightweight client for the ElevenFlow Vercel API.
// It handles proxy rotation with countdown polling so callers don't need to
// know anything about 1ip.vn or Supabase.
package proxyserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"elevenflow/internal/diaglog"
)

// DefaultServerURL and DefaultAppSecret can be overridden at build time via ldflags:
//
//	wails build -ldflags "-X elevenflow/internal/proxyserver.DefaultServerURL=https://your.vercel.app \
//	                       -X elevenflow/internal/proxyserver.DefaultAppSecret=your-secret"
var (
	DefaultServerURL = "https://server-nine-xi-24.vercel.app"
	DefaultAppSecret = "6276747e7c73e3ac957f8e328c5625ee393ea864b9ff39fa"
)

// RotateResponse mirrors the JSON returned by /api/proxy/rotate.
type RotateResponse struct {
	Status      string `json:"status"`       // "ok" | "wait"
	Seconds     int    `json:"seconds"`      // > 0 when status=="wait"
	ProxyHTTP   string `json:"proxy_http"`   // http://user:pass@host:port
	ProxySOCKS5 string `json:"proxy_socks5"` // socks5://user:pass@host:port
	Error       string `json:"error"`
}

// Client calls the Vercel API endpoints. Mỗi instance gen 1 sessionID (UUID
// v4) khi tạo — server dùng sessionID để gán lease cho ĐÚNG client, tránh
// 2 user cầm chung 1 proxy key cùng thời điểm.
type Client struct {
	serverURL string
	secret    string
	sessionID string
	hc        *http.Client

	mu                sync.Mutex
	bearerToken       string
	refreshToken      string
	tokenExpiryUnix   int64
	sessionEmail      string
	deviceFingerprint string
}

// New creates a Client with explicit server URL and secret.
func New(serverURL, secret string) *Client {
	return &Client{
		serverURL: serverURL,
		secret:    secret,
		sessionID: newSessionID(),
		hc:        &http.Client{Timeout: 30 * time.Second},
	}
}

// SessionID trả ID của client (debug / log).
func (c *Client) SessionID() string { return c.sessionID }

// ServerURL base URL Vercel (không slash cuối logic do nối path).
func (c *Client) ServerURL() string { return c.serverURL }

func (c *Client) applyAuthHeaders(req *http.Request) {
	req.Header.Set("X-App-Secret", c.secret)
	c.mu.Lock()
	bt := c.bearerToken
	df := c.deviceFingerprint
	c.mu.Unlock()
	if bt != "" {
		req.Header.Set("Authorization", "Bearer "+bt)
	}
	if df != "" {
		req.Header.Set("X-Device-ID", df)
	}
}

// SetDeviceFingerprint gửi kèm mọi request proxy khi COMMERCIAL_AUTH (khóa thiết bị).
func (c *Client) SetDeviceFingerprint(fp string) {
	c.mu.Lock()
	c.deviceFingerprint = fp
	c.mu.Unlock()
}

// ApplyCommercialSession lưu JWT sau đăng nhập (expiresInSec từ Supabase, vd 3600).
func (c *Client) ApplyCommercialSession(access, refresh string, expiresInSec int, email string) {
	if expiresInSec <= 0 {
		expiresInSec = 3600
	}
	c.mu.Lock()
	c.bearerToken = strings.TrimSpace(access)
	c.refreshToken = strings.TrimSpace(refresh)
	c.tokenExpiryUnix = time.Now().Unix() + int64(expiresInSec)
	c.sessionEmail = email
	c.mu.Unlock()
}

// ClearCommercialSession xóa JWT (đăng xuất).
func (c *Client) ClearCommercialSession() {
	c.mu.Lock()
	c.bearerToken = ""
	c.refreshToken = ""
	c.tokenExpiryUnix = 0
	c.sessionEmail = ""
	c.mu.Unlock()
}

// SessionSnapshot trả token hiện tại để lưu file (ok=false nếu chưa đăng nhập).
func (c *Client) SessionSnapshot() (access, refresh string, exp int64, email string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bearerToken == "" {
		return "", "", 0, "", false
	}
	return c.bearerToken, c.refreshToken, c.tokenExpiryUnix, c.sessionEmail, true
}

// EnsureFreshToken gia hạn access_token khi sắp hết (commercial).
func (c *Client) EnsureFreshToken(ctx context.Context) error {
	c.mu.Lock()
	refresh := c.refreshToken
	access := c.bearerToken
	exp := c.tokenExpiryUnix
	secret := c.secret
	base := c.serverURL
	deviceFP := c.deviceFingerprint
	c.mu.Unlock()
	if access == "" {
		return nil
	}
	if refresh == "" {
		if time.Now().Unix() >= exp {
			return fmt.Errorf("phiên đã hết hạn, vui lòng đăng nhập lại")
		}
		return nil
	}
	if time.Now().Unix() < exp-150 {
		return nil
	}
	lr, err := refreshAccess(ctx, base, secret, refresh, deviceFP)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.bearerToken = lr.AccessToken
	if lr.RefreshToken != "" {
		c.refreshToken = lr.RefreshToken
	}
	if lr.ExpiresIn > 0 {
		c.tokenExpiryUnix = time.Now().Unix() + int64(lr.ExpiresIn)
	} else {
		c.tokenExpiryUnix = time.Now().Unix() + 3600
	}
	if lr.UserEmail != "" {
		c.sessionEmail = lr.UserEmail
	}
	c.mu.Unlock()
	return nil
}

// newSessionID gen UUID v4 không dùng external lib (Go stdlib có
// crypto/rand). Format: 8-4-4-4-12 hex.
func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0F) | 0x40 // version 4
	b[8] = (b[8] & 0x3F) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Default creates a Client using ELEVENFLOW_SERVER_URL / ELEVENFLOW_APP_SECRET env vars
// with fallback to DefaultServerURL / DefaultAppSecret.
func Default() *Client {
	u := os.Getenv("ELEVENFLOW_SERVER_URL")
	if u == "" {
		u = DefaultServerURL
	}
	s := os.Getenv("ELEVENFLOW_APP_SECRET")
	if s == "" {
		s = DefaultAppSecret
	}
	return New(u, s)
}

// Rotate calls POST /api/proxy/rotate once and returns the result.
func (c *Client) Rotate(ctx context.Context) (RotateResponse, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.serverURL+"/api/proxy/rotate",
		bytes.NewBufferString("{}"),
	)
	if err != nil {
		return RotateResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyAuthHeaders(req)

	resp, err := c.hc.Do(req)
	if err != nil {
		return RotateResponse{}, fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()

	var r RotateResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return RotateResponse{}, fmt.Errorf("invalid server response: %w", err)
	}
	if r.Error != "" {
		return r, fmt.Errorf("server: %s", r.Error)
	}
	return r, nil
}

// bestProxy trả về HTTP proxy (Firefox không hỗ trợ SOCKS5 với auth).
func bestProxy(r RotateResponse) string {
	if r.ProxyHTTP != "" {
		return r.ProxyHTTP
	}
	return r.ProxySOCKS5
}

// CurrentProxyResponse mirrors JSON từ GET /api/proxy/current.
type CurrentProxyResponse struct {
	ProxyHTTP   string `json:"proxy_http"`
	ProxySOCKS5 string `json:"proxy_socks5"`
	Error       string `json:"error"`
}

// Current gọi GET /api/proxy/current — trả proxy hiện tại NGAY, không gọi
// 1ip.vn, không kích hoạt rotation. Dùng cho lần đầu lấy IP trước khi biết
// IP có bị ElevenLabs chặn không.
func (c *Client) Current(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet,
		c.serverURL+"/api/proxy/current",
		nil,
	)
	if err != nil {
		return "", err
	}
	c.applyAuthHeaders(req)

	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()

	var r CurrentProxyResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("invalid server response: %w", err)
	}
	if r.Error != "" {
		return "", fmt.Errorf("server: %s", r.Error)
	}
	p := bestProxy(RotateResponse{ProxyHTTP: r.ProxyHTTP, ProxySOCKS5: r.ProxySOCKS5})
	if p == "" {
		return "", fmt.Errorf("máy chủ chưa có kết nối mạng khả dụng")
	}
	return p, nil
}

// ProxyPoolCapacityResponse mirrors GET /api/proxy/capacity.
type ProxyPoolCapacityResponse struct {
	PoolCount int    `json:"pool_count"`
	MaxLeases int    `json:"max_leases"`
	Error     string `json:"error"`
}

// ProxyPoolCapacity gọi GET /api/proxy/capacity — số dòng proxy is_active (còn hạn gói)
// và max_leases/session (khớp server) để client autoscale NumWorkers.
func (c *Client) ProxyPoolCapacity(ctx context.Context) (poolCount, maxLeases int, err error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet,
		c.serverURL+"/api/proxy/capacity",
		nil,
	)
	if err != nil {
		return 0, 0, err
	}
	c.applyAuthHeaders(req)
	req.Header.Set("X-Session-ID", c.sessionID)

	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()

	var r ProxyPoolCapacityResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return 0, 0, fmt.Errorf("invalid server response: %w", err)
	}
	if r.Error != "" {
		return 0, 0, fmt.Errorf("server: %s", r.Error)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("capacity HTTP %d", resp.StatusCode)
	}
	return r.PoolCount, r.MaxLeases, nil
}

// RotateWithWait gọi Rotate trong vòng lặp cho đến khi status=="ok" (IP mới).
// Dùng khi cần BUỘC đổi IP (ví dụ sau khi bị ElevenLabs chặn).
// emit nhận message đếm ngược, có thể nil.
func (c *Client) RotateWithWait(ctx context.Context, emit func(string)) (string, error) {
	if emit == nil {
		emit = func(string) {}
	}
	for {
		r, err := c.Rotate(ctx)
		if err != nil {
			return "", err
		}
		if r.Status == "ok" {
			diaglog.Append("proxy_rotate_ok", map[string]any{
				"proxy": diaglog.RedactProxyURL(bestProxy(r)),
			})
			return bestProxy(r), nil
		}
		diaglog.Append("proxy_rotate_wait", map[string]any{
			"status":  r.Status,
			"seconds": r.Seconds,
			"error":   r.Error,
		})
		secs := r.Seconds
		if secs <= 0 {
			secs = 15
		}
		for i := secs; i > 0; i-- {
			if leaseWaitShouldEmit(i, secs) {
				emit("Đang đổi địa chỉ mạng…")
			}
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				diaglog.Append("proxy_rotate_ctx_done", map[string]any{"err": ctx.Err().Error()})
				return "", ctx.Err()
			}
		}
	}
}

// LeaseResponse mirrors /api/proxy/lease response.
type LeaseResponse struct {
	Status          string `json:"status"` // "ok" | "wait"
	Seconds         int    `json:"seconds"`
	Reason          string `json:"reason"`
	LeaseToken      string `json:"lease_token"`
	ProxyHTTP       string `json:"proxy_http"`
	ProxySOCKS5     string `json:"proxy_socks5"`
	CooldownSeconds int    `json:"cooldown_seconds"`
	Error           string `json:"error"`
}

// Lease gọi POST /api/proxy/lease 1 lần. excludeURL = URL vừa bị ban (server
// đảm bảo không cấp lại). Trả LeaseResponse — caller xử lý status="wait".
func (c *Client) Lease(ctx context.Context, excludeURL string) (LeaseResponse, error) {
	body := map[string]any{}
	if excludeURL != "" {
		body["exclude_url"] = excludeURL
	}
	bs, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.serverURL+"/api/proxy/lease", bytes.NewReader(bs))
	if err != nil {
		return LeaseResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyAuthHeaders(req)
	req.Header.Set("X-Session-ID", c.sessionID)

	resp, err := c.hc.Do(req)
	if err != nil {
		return LeaseResponse{}, fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()

	var r LeaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return LeaseResponse{}, fmt.Errorf("invalid server response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return r, fmt.Errorf("unauthorized")
	}
	if r.Error != "" {
		return r, fmt.Errorf("server: %s", r.Error)
	}
	return r, nil
}

// bestLeaseProxy: ưu tiên HTTP proxy URL từ response lease.
func bestLeaseProxy(r LeaseResponse) string {
	if r.ProxyHTTP != "" {
		return r.ProxyHTTP
	}
	return r.ProxySOCKS5
}

// maxLeasePollDuration — tránh treo UI vô hạn khi pool đầy / 1ip cooldown lặp.
const maxLeasePollDuration = 25 * time.Minute

// LeaseWithWait poll Lease() cho đến khi status="ok" hoặc ctx hủy.
// emit nhận log countdown, có thể nil. Khác RotateWithWait: Lease có
// excludeURL — sau khi 1 IP bị ban, server cam kết không cấp lại URL đó.
func (c *Client) LeaseWithWait(ctx context.Context, excludeURL string, emit func(string)) (LeaseResponse, error) {
	if emit == nil {
		emit = func(string) {}
	}
	deadline := time.Now().Add(maxLeasePollDuration)
	var lastReason string
	for {
		if err := ctx.Err(); err != nil {
			diaglog.Append("proxy_lease_ctx_done", map[string]any{
				"exclude": diaglog.RedactProxyURL(excludeURL),
				"err":     err.Error(),
			})
			return LeaseResponse{}, err
		}
		if !time.Now().Before(deadline) {
			msg := strings.TrimSpace(lastReason)
			if msg == "" {
				msg = "(không có chi tiết từ máy chủ)"
			}
			diaglog.Append("proxy_lease_timeout", map[string]any{
				"exclude":        diaglog.RedactProxyURL(excludeURL),
				"lastReason":     msg,
				"maxDurationSec": int(maxLeasePollDuration.Seconds()),
			})
			return LeaseResponse{}, fmt.Errorf(
				"hết thời gian chờ gán kết nối (~%v). Gần nhất: %s — thử lại sau vài phút, "+
					"hoặc liên hệ người quản trị nếu vẫn lỗi.",
				maxLeasePollDuration, msg)
		}
		r, err := c.Lease(ctx, excludeURL)
		if err != nil {
			diaglog.Append("proxy_lease_error", map[string]any{
				"exclude": diaglog.RedactProxyURL(excludeURL),
				"error":   err.Error(),
			})
			return LeaseResponse{}, err
		}
		if r.Status == "ok" {
			diaglog.Append("proxy_lease_ok", map[string]any{
				"excludeWas": diaglog.RedactProxyURL(excludeURL),
				"proxy":      diaglog.RedactProxyURL(bestLeaseProxy(r)),
				"cooldown":   r.CooldownSeconds,
			})
			return r, nil
		}
		diaglog.Append("proxy_lease_wait", map[string]any{
			"exclude": diaglog.RedactProxyURL(excludeURL),
			"status":  r.Status,
			"seconds": r.Seconds,
			"reason":  r.Reason,
			"err":     r.Error,
		})
		lastReason = r.Reason
		secs := r.Seconds
		if secs <= 0 {
			secs = 15
		}
		reason := r.Reason
		human := friendlyLeaseReason(reason)
		if human == "" {
			human = "đang chờ máy chủ"
		}
		for i := secs; i > 0; i-- {
			if leaseWaitShouldEmit(i, secs) {
				emit(fmt.Sprintf("Đang chờ… %s", human))
			}
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				diaglog.Append("proxy_lease_ctx_done", map[string]any{
					"exclude": diaglog.RedactProxyURL(excludeURL),
					"err":     ctx.Err().Error(),
				})
				return LeaseResponse{}, ctx.Err()
			}
		}
	}
}

// Release gọi POST /api/proxy/release. banned=true → key vào cooldown 60s.
// Idempotent server-side: gọi với token đã release / sai session = no-op.
func (c *Client) Release(ctx context.Context, leaseToken string, banned bool) error {
	if leaseToken == "" {
		return nil
	}
	suffix := leaseToken
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	diaglog.Append("proxy_release_req", map[string]any{"banned": banned, "tokenSuffix": suffix})
	body, _ := json.Marshal(map[string]any{
		"lease_token": leaseToken,
		"banned":      banned,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.serverURL+"/api/proxy/release", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyAuthHeaders(req)
	req.Header.Set("X-Session-ID", c.sessionID)

	resp, err := c.hc.Do(req)
	if err != nil {
		diaglog.Append("proxy_release_err", map[string]any{"banned": banned, "error": err.Error()})
		return fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		diaglog.Append("proxy_release_http", map[string]any{"banned": banned, "status": resp.StatusCode})
		return fmt.Errorf("release HTTP %d", resp.StatusCode)
	}
	diaglog.Append("proxy_release_ok", map[string]any{"banned": banned})
	return nil
}

// Heartbeat gọi POST /api/proxy/heartbeat với danh sách token đang giữ.
// Trả số lease server đã refresh (debug).
func (c *Client) Heartbeat(ctx context.Context, leaseTokens []string) (int, error) {
	if len(leaseTokens) == 0 {
		return 0, nil
	}
	body, _ := json.Marshal(map[string]any{"lease_tokens": leaseTokens})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.serverURL+"/api/proxy/heartbeat", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyAuthHeaders(req)
	req.Header.Set("X-Session-ID", c.sessionID)

	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()
	var r struct {
		Refreshed int    `json:"refreshed"`
		Error     string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return 0, err
	}
	if r.Error != "" {
		return 0, fmt.Errorf("server: %s", r.Error)
	}
	return r.Refreshed, nil
}

// HealthCheck returns true if the server responds to /api/health.
func (c *Client) HealthCheck(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL+"/api/health", nil)
	if err != nil {
		return false
	}
	c.applyAuthHeaders(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func friendlyLeaseReason(reason string) string {
	r := strings.ToLower(strings.TrimSpace(reason))
	switch {
	case r == "":
		return ""
	case strings.Contains(r, "session_lease_cap"):
		return "đã đủ số kết nối đồng thời"
	case strings.Contains(r, "all proxies leased") || strings.Contains(r, "all proxies leased or in"):
		return "chưa có kết nối rảnh (đang dùng hoặc nghỉ vài chục giây)"
	// Không hiển thị tên nhà cung cấp / API ngoài — chỉ mô tả hành vi.
	case strings.Contains(r, "1ip") || strings.Contains(r, "changeip") ||
		strings.Contains(r, "rotation_wait") || strings.Contains(r, "rotation_provider"):
		return "đang chờ địa chỉ mạng mới (thường vài chục giây)"
	case strings.Contains(r, "cooldown") || strings.Contains(r, "leased"):
		return "đang chờ máy chủ sẵn sàng kết nối"
	default:
		return "đang chờ máy chủ"
	}
}

// leaseWaitShouldEmit — true một lần đầu mỗi chu kỳ chờ (i == secs), không log theo từng giây.
func leaseWaitShouldEmit(i, secs int) bool {
	return i == secs
}
