package webview2bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// HomeproxyKeyProvider is a direct client for one homeproxy.vn rotating-IP
// line — evaluated 2026-08-22 as a candidate to replace/supplement
// proxyxoay.shop long-term (operator's call: "stress thử vendor này xem có
// ngon không để gắn bó lâu dài"). Same shape as ProxyxoayKeyProvider
// (proxyxoay_provider.go) — direct vendor API call, no Vercel relay — but a
// materially different vendor model, confirmed live 2026-08-22 with 5 real
// keys (not guessed):
//
//	GET https://app.homeproxy.vn/api/v3/users/rotatev2?token=...&checkOnly=true
//	{"status":"success","message":"Sẵn sàng xoay",
//	 "proxy":"14.187.152.21:51153:elnajones502:20-elRSAlWoepIBq0liRrA",
//	 "ip":"14.187.152.21","lastRotate":"2026-08-21T17:33:11.271Z","timeRemaining":0}
//
// proxy = "host:port:user:pass" (4 fields, unlike proxyxoay's user/pass-less
// "host:port::"). Bad token, confirmed live:
//
//	{"status":"error","error":{"code":"unauthorized","message":"invalid or expired token"}}
//
// Model difference from proxyxoay that matters for how this provider is
// built: proxyxoay hands back a NEW IP on every get.php call and that IP
// expires on its own after a vendor-reported TTL (must keep refreshing
// before expiry). homeproxy instead gives you a STICKY IP that stays valid
// indefinitely on its own — checkOnly=true (no side effects, confirmed live)
// just reads the current one — and only changes when YOU explicitly call
// rotatev2 (real rotate), which itself is rate-limited (timeRemaining
// seconds until the next rotate is allowed; observed 0 = allowed now on all
// 5 fresh keys — the vendor's own doc example additionally shows a
// checkOnly read returning timeRemaining:99 when a recent rotate is still
// cooling down; a live cooldown-rejection response body has NOT been
// observed yet, so unlike proxyxoay's message-regex cooldown detection this
// reads timeRemaining as a structured field directly wherever the API
// exposes it, no text pattern to keep in sync).
//
// Consequence: no background refresh loop needed to keep an IP from
// expiring (there's nothing to expire) — Acquire does one checkOnly read to
// pick up whatever's currently live (including a rotate the operator did by
// hand outside this program), MarkUnhealthyAndRotate does a real rotate on
// ban/network failure, same as every other provider's rotate contract.
//
// UNVERIFIED: proxy protocol. The vendor's docs/response never say http vs
// socks5 — defaulting to http:// (same assumption proxyxoay_provider.go
// made for a same-market Vietnamese vendor, which worked live) since
// LocalProxy.SetUpstream accepts http/https/socks5 uniformly either way.
// If real TTS traffic through this provider fails at the connect step
// (not at hCaptcha/ElevenLabs — a lower-level dial failure), that's the
// signal to try socks5:// instead; this file is exactly one word to change.
type HomeproxyKeyProvider struct {
	name  string
	token string

	mu         sync.Mutex
	current    Lease
	generation int64
	dead       bool
	lastErr    string
}

const (
	homeproxyHTTPTimeout = 15 * time.Second
	homeproxyBaseURL     = "https://app.homeproxy.vn/api/v3/users/rotatev2"
)

func NewHomeproxyKeyProvider(label, token string) *HomeproxyKeyProvider {
	return &HomeproxyKeyProvider{
		name:  "homeproxy-" + label,
		token: token,
	}
}

func (p *HomeproxyKeyProvider) Name() string { return p.name }

type homeproxySuccess struct {
	Status        string `json:"status"`
	Message       string `json:"message"`
	Proxy         string `json:"proxy"`
	IP            string `json:"ip"`
	LastRotate    string `json:"lastRotate"`
	TimeRemaining int    `json:"timeRemaining"`
}

type homeproxyErrorResp struct {
	Status string `json:"status"`
	Error  struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type homeproxyResult struct {
	url           string
	dead          bool // confirmed live: status="error", error.code="unauthorized" — invalid/expired token, not coming back
	timeRemaining int  // > 0: vendor's own cooldown before the next real rotate is allowed
}

func homeproxyParseProxy(s string) (string, error) {
	// "host:port:user:pass" — confirmed live shape, 4 colon-separated fields
	// (proxyxoay's "host:port::" always has empty trailing fields; this
	// vendor's user/pass are real). SplitN(..., 4) rather than
	// fmt.Sscanf("%[^:]...") — Go's fmt package does NOT support the C
	// scanf "%[...]" scanset verb (confirmed live 2026-08-22: the Sscanf
	// version failed on every single well-formed proxy string, not just
	// malformed ones — real bug, not a vendor data problem).
	parts := strings.SplitN(s, ":", 4)
	if len(parts) != 4 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("homeproxy: unexpected proxy field %q", s)
	}
	host, port, user, pass := parts[0], parts[1], parts[2], parts[3]
	return fmt.Sprintf("http://%s:%s@%s:%s", url.QueryEscape(user), url.QueryEscape(pass), host, port), nil
}

// callAPI does one GET to homeproxy.vn. checkOnly=true never consumes a
// rotate (confirmed live: read-only, same current proxy returned every
// time) — use it for Acquire (pick up whatever's currently live) and
// checkOnly=false only from an actual MarkUnhealthyAndRotate.
func (p *HomeproxyKeyProvider) callAPI(ctx context.Context, checkOnly bool) (homeproxyResult, error) {
	u := fmt.Sprintf("%s?token=%s", homeproxyBaseURL, url.QueryEscape(p.token))
	if checkOnly {
		u += "&checkOnly=true"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return homeproxyResult{}, err
	}
	client := &http.Client{Timeout: homeproxyHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return homeproxyResult{}, fmt.Errorf("homeproxy unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return homeproxyResult{}, fmt.Errorf("homeproxy invalid response: %w", err)
	}

	var ok homeproxySuccess
	if json.Unmarshal(body, &ok) == nil && ok.Status == "success" {
		proxyURL, perr := homeproxyParseProxy(ok.Proxy)
		if perr != nil {
			return homeproxyResult{}, perr
		}
		return homeproxyResult{url: proxyURL, timeRemaining: ok.TimeRemaining}, nil
	}

	var errResp homeproxyErrorResp
	if json.Unmarshal(body, &errResp) == nil && errResp.Status == "error" {
		msg := errResp.Error.Message
		if msg == "" {
			msg = errResp.Error.Code
		}
		if errResp.Error.Code == "unauthorized" {
			return homeproxyResult{}, fmt.Errorf("homeproxy key dead: %s", &homeproxyDeadError{msg: msg})
		}
		// Any other error code: not documented, treat as transient — do not
		// mark dead over an error shape never seen live.
		return homeproxyResult{}, fmt.Errorf("homeproxy transient: %s", msg)
	}

	return homeproxyResult{}, fmt.Errorf("homeproxy: unrecognized response shape: %s", string(body))
}

type homeproxyDeadError struct{ msg string }

func (e *homeproxyDeadError) Error() string { return e.msg }

// Acquire: first call for this key — checkOnly read (no side effects) to
// pick up whatever proxy is currently live, same contract as every other
// provider's Acquire (idempotent per workerID via the caller's own lease
// cache, this provider itself is single-lease — matches proxyxoay's shape).
func (p *HomeproxyKeyProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	p.mu.Lock()
	cur := p.current
	dead := p.dead
	lastErr := p.lastErr
	p.mu.Unlock()

	if cur.URL != "" {
		return cur, nil
	}
	if dead {
		return Lease{}, fmt.Errorf("%s: key dead: %s", p.name, lastErr)
	}

	res, err := p.callAPI(ctx, true)
	if err != nil {
		var deadErr *homeproxyDeadError
		p.mu.Lock()
		p.lastErr = err.Error()
		p.dead = p.dead || errors.As(err, &deadErr)
		p.mu.Unlock()
		return Lease{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current.URL == "" {
		p.generation++
		p.current = Lease{URL: res.url, AcquiredAt: time.Now(), Generation: p.generation}
	}
	return p.current, nil
}

// MarkUnhealthyAndRotate: a real rotate (checkOnly=false) — see doc comment
// on HomeproxyKeyProvider for why there is no background refresh loop and
// why cooldown is read from the structured timeRemaining field rather than
// a message-text pattern. Same "wait out the vendor's own countdown, then
// ask again" shape as proxyxoay_provider.go's fix (2026-08-21) — retrying
// immediately against a still-cooling-down key can only hand back the SAME
// (already banned) IP.
func (p *HomeproxyKeyProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, kind FailureKind, emit func(string)) (Lease, error) {
	if emit == nil {
		emit = func(string) {}
	}
	p.mu.Lock()
	if p.current.URL != "" && p.current.Generation != oldLease.Generation {
		cur := p.current
		p.mu.Unlock()
		return cur, nil
	}
	p.mu.Unlock()

	emit("Đang đổi địa chỉ mạng…")
	res, err := p.callAPI(ctx, false)

	if err == nil && res.timeRemaining > 0 {
		// Vendor accepted the call but the returned IP hasn't actually
		// changed yet (still on cooldown) — wait it out, then ask again,
		// same lesson as proxyxoay's cooldown fix.
		wait := time.Duration(res.timeRemaining+1) * time.Second
		emit(fmt.Sprintf("Đang đợi %ds trước khi đổi địa chỉ mạng mới…", res.timeRemaining+1))
		select {
		case <-ctx.Done():
			return Lease{}, ctx.Err()
		case <-time.After(wait):
		}
		res, err = p.callAPI(ctx, false)
	}

	if err != nil {
		var deadErr *homeproxyDeadError
		p.mu.Lock()
		p.lastErr = err.Error()
		p.dead = p.dead || errors.As(err, &deadErr)
		cur := p.current
		p.mu.Unlock()
		if cur.URL != "" {
			log.Printf("[homeproxy] %s: rotate failed, reusing stale lease as last resort: %v", p.name, err)
			return cur, nil
		}
		return Lease{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.dead = false
	p.lastErr = ""
	p.generation++
	p.current = Lease{URL: res.url, AcquiredAt: time.Now(), Generation: p.generation}
	return p.current, nil
}

// Release is a no-op: sticky IP, nothing to tear down (see doc comment).
func (p *HomeproxyKeyProvider) Release(workerID int, lease Lease) {}
