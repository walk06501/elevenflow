package webview2bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProxyxoayKeyProvider is a direct client for one proxyxoay.shop rotating-IP
// API key — calls the vendor's own get.php endpoint straight from this
// process, no Vercel relay / Supabase in the path at all (unlike
// SharedCurrentProvider, which goes through ELEVENFLOW_SERVER_URL). Added
// 2026-08-18 as a temporary fallback while the VPN sources are IP-blocked
// across their whole range — operator gave 3 raw keys directly rather than
// routing through the old relay, explicitly to cut that dependency.
//
// Contract verified against the existing Vercel-relay implementation
// (elevenflow's own server/lib/proxyxoay.ts, already live and tested there):
//
//	GET https://proxyxoay.shop/api/get.php?key=...&nhamang=random&tinhthanh=0&whitelist=
//	{"status":100,"message":"proxy nay se die sau 1318s",
//	 "proxyhttp":"host:port::","proxysocks5":"host:port::", ...}
//
// status=100 → proxyhttp/proxysocks5 are "host:port::" (2 trailing fields —
// username/password — are always empty; the vendor authenticates by
// IP-whitelist or its own session, not user/pass). status=101/102 → key is
// permanently dead (not found / out of credit or expired). Anything else
// (103 out of stock, 104 unknown, network error) is transient — retry later,
// key is NOT dead.
//
// Unlike the WireGuard providers there is no real tunnel to hold open: this
// is a plain host:port HTTP/SOCKS5 proxy. The one thing that DOES need
// active management is the vendor-side session TTL (the operator's package
// on these 3 keys renews every ~60s) — a background loop keeps calling
// get.php a little before that TTL so a long-lived WebView2 session's
// already-configured proxy keeps working without the caller ever noticing.
// The vendor's own gateway host:port is USUALLY stable across calls for the
// same key (observed), but not guaranteed — if it does change mid-session,
// that one running session's already-configured proxy breaks until the
// session pool's normal idle/ban recovery cycles it, same bounded,
// self-healing trade-off already accepted elsewhere in this codebase (see
// session_pool.go's own doc comment) rather than building a live in-session
// proxy swap WebView2 does not cleanly support anyway.
type ProxyxoayKeyProvider struct {
	name      string
	apiKey    string
	whitelist string

	mu         sync.Mutex
	current    Lease
	generation int64
	dead       bool
	lastErr    string

	stopOnce sync.Once
	stop     chan struct{}
}

const (
	proxyxoayRefreshInterval = 50 * time.Second // a bit under the operator's observed ~60s package TTL
	proxyxoayHTTPTimeout     = 15 * time.Second
	proxyxoayBaseURL         = "https://proxyxoay.shop/api/get.php"
)

// NewProxyxoayKeyProvider starts the background refresh loop immediately so
// the first real Acquire() does not have to block on a network call.
func NewProxyxoayKeyProvider(label, apiKey, whitelist string) *ProxyxoayKeyProvider {
	p := &ProxyxoayKeyProvider{
		name:      "proxyxoay-" + label,
		apiKey:    apiKey,
		whitelist: whitelist,
		stop:      make(chan struct{}),
	}
	go p.refreshLoop()
	return p
}

func (p *ProxyxoayKeyProvider) Name() string { return p.name }

// Stop ends the background refresh loop — call on shutdown/reload. Never
// called from a live production path today (providers live for the process
// lifetime, same as every other VPN source in main.go), included so tests
// and any future hot-reload path have a clean way to stop the goroutine.
func (p *ProxyxoayKeyProvider) Stop() {
	p.stopOnce.Do(func() { close(p.stop) })
}

type proxyxoayAPIResponse struct {
	Status      int    `json:"status"`
	Message     string `json:"message"`
	Comen       string `json:"comen"`
	ProxyHTTP   string `json:"proxyhttp"`
	ProxySOCKS5 string `json:"proxysocks5"`
}

func parseHostPort(s string) (string, int, bool) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return "", 0, false
	}
	host := strings.TrimSpace(parts[0])
	port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if host == "" || err != nil || port <= 0 {
		return "", 0, false
	}
	return host, port, true
}

// proxyxoayResult is callAPI's full classification of one get.php call.
type proxyxoayResult struct {
	url             string
	dead            bool // permanently dead (key not found / out of credit) — stop trying
	ttlSeconds      int  // > 0 on success: how long THIS proxy is good for, parsed from message
	cooldownSeconds int  // > 0 on a "wait N more seconds" rejection — transient, NOT dead
}

// proxyxoayCooldownPattern matches the vendor's own rate-limit rejection,
// e.g. "Con 8s moi co the doi proxy" ("còn 8s mới có thể đổi proxy" without
// diacritics) — confirmed live 2026-08-18: this comes back under the SAME
// status code (101) the vendor also uses for a truly dead key, so status
// alone cannot tell the two apart. The message text is the only reliable
// signal. Checked BEFORE the status-code switch below for exactly that
// reason: a cooldown is never permanent, regardless of which status number
// carries it.
var proxyxoayCooldownPattern = regexp.MustCompile(`(?i)con\s*(\d+)\s*s\b`)

// proxyxoayTTLPattern parses a successful response's own "proxy nay se die
// sau 1318s" message so refreshOnce can schedule the next call at the
// vendor's real expiry instead of a guessed fixed interval — calling before
// the key's own cooldown window elapses is exactly what produces the
// rejection proxyxoayCooldownPattern matches (confirmed live: a fixed 50s
// ticker fired earlier than a ~60s+ real window and got rejected every
// single cycle).
var proxyxoayTTLPattern = regexp.MustCompile(`sau\s*(\d+)s`)

// callAPI does one GET to proxyxoay.shop and classifies the result. dead is
// true ONLY for a message with no cooldown hint under status 101/102 (key
// not found / out of credit) — see proxyxoayCooldownPattern's doc comment
// for why the cooldown case is checked first and never treated as dead.
func (p *ProxyxoayKeyProvider) callAPI(ctx context.Context) (proxyxoayResult, error) {
	u := fmt.Sprintf(
		"%s?key=%s&nhamang=random&tinhthanh=0&whitelist=%s",
		proxyxoayBaseURL, url.QueryEscape(p.apiKey), url.QueryEscape(p.whitelist),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return proxyxoayResult{}, err
	}
	client := &http.Client{Timeout: proxyxoayHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return proxyxoayResult{}, fmt.Errorf("proxyxoay unreachable: %w", err)
	}
	defer resp.Body.Close()

	var data proxyxoayAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return proxyxoayResult{}, fmt.Errorf("proxyxoay invalid response: %w", err)
	}
	msg := data.Message
	if msg == "" {
		msg = data.Comen
	}

	if m := proxyxoayCooldownPattern.FindStringSubmatch(msg); m != nil {
		secs, _ := strconv.Atoi(m[1])
		if secs <= 0 {
			secs = 5
		}
		return proxyxoayResult{}, fmt.Errorf("proxyxoay cooldown, %ds left: %w",
			secs, &proxyxoayCooldownError{seconds: secs, msg: msg})
	}

	switch data.Status {
	case 100:
		host, port, ok := parseHostPort(data.ProxyHTTP)
		if !ok {
			return proxyxoayResult{}, fmt.Errorf("proxyxoay: response missing usable proxyhttp (%q)", data.ProxyHTTP)
		}
		ttl := 0
		if m := proxyxoayTTLPattern.FindStringSubmatch(msg); m != nil {
			ttl, _ = strconv.Atoi(m[1])
		}
		return proxyxoayResult{url: fmt.Sprintf("http://%s:%d", host, port), ttlSeconds: ttl}, nil
	case 101, 102:
		if msg == "" {
			msg = fmt.Sprintf("status=%d", data.Status)
		}
		return proxyxoayResult{}, fmt.Errorf("proxyxoay key dead: %s", &proxyxoayDeadError{msg: msg})
	default:
		if msg == "" {
			msg = fmt.Sprintf("status=%d", data.Status)
		}
		return proxyxoayResult{}, fmt.Errorf("proxyxoay transient: %s", msg)
	}
}

// proxyxoayCooldownError/proxyxoayDeadError let refreshOnce/Acquire tell the
// 3 outcomes (ok / cooldown-transient / permanently-dead) apart via
// errors.As without string-matching error text a second time.
type proxyxoayCooldownError struct {
	seconds int
	msg     string
}

func (e *proxyxoayCooldownError) Error() string { return e.msg }

type proxyxoayDeadError struct{ msg string }

func (e *proxyxoayDeadError) Error() string { return e.msg }

// refreshLoop calls the API once immediately, then reschedules itself after
// EVERY call based on what that call actually told us: a live TTL (wait
// until just before it expires), a cooldown (wait exactly that long), or
// neither (fall back to proxyxoayRefreshInterval as a safe default so a
// malformed/unexpected response can never spin-loop the vendor's API).
// Fixed-ticker was the original design and is exactly what caused the
// live 2026-08-18 bug (see proxyxoayCooldownPattern's doc comment) — a
// dynamic timer means the interval now always comes from the vendor's own
// answer instead of a guess.
func (p *ProxyxoayKeyProvider) refreshLoop() {
	for {
		wait := p.refreshOnce(context.Background())
		select {
		case <-p.stop:
			return
		case <-time.After(wait):
		}
	}
}

// refreshOnce makes one call and returns how long to wait before the next
// one — see refreshLoop's doc comment for why this is dynamic now.
func (p *ProxyxoayKeyProvider) refreshOnce(ctx context.Context) time.Duration {
	ctx, cancel := context.WithTimeout(ctx, proxyxoayHTTPTimeout+5*time.Second)
	defer cancel()
	res, err := p.callAPI(ctx)

	p.mu.Lock()
	defer p.mu.Unlock()

	var cooldown *proxyxoayCooldownError
	if errors.As(err, &cooldown) {
		// Transient rate-limit, not dead — keep whatever lease we already
		// have (still valid) and just wait out the vendor's own countdown.
		p.lastErr = err.Error()
		return time.Duration(cooldown.seconds+2) * time.Second
	}
	var deadErr *proxyxoayDeadError
	if errors.As(err, &deadErr) {
		p.lastErr = err.Error()
		if !p.dead {
			log.Printf("[proxyxoay] %s: key marked dead: %v", p.name, deadErr)
		}
		p.dead = true
		return proxyxoayRefreshInterval
	}
	if err != nil {
		// Network hiccup / malformed response — transient, retry on the
		// default cadence, never mark dead over this.
		p.lastErr = err.Error()
		return proxyxoayRefreshInterval
	}

	p.dead = false
	p.lastErr = ""
	if p.current.URL != res.url {
		p.generation++
		p.current = Lease{URL: res.url, AcquiredAt: time.Now(), Generation: p.generation}
		log.Printf("[proxyxoay] %s: proxy ready (%s, ttl=%ds)", p.name, res.url, res.ttlSeconds)
	}
	if res.ttlSeconds > proxyxoaySafetyMarginSeconds {
		return time.Duration(res.ttlSeconds-proxyxoaySafetyMarginSeconds) * time.Second
	}
	return proxyxoayRefreshInterval
}

// proxyxoaySafetyMarginSeconds: refresh this many seconds before the
// vendor's own reported expiry, not exactly at it — avoids a request being
// mid-flight through the old proxy right as it dies.
const proxyxoaySafetyMarginSeconds = 5

func (p *ProxyxoayKeyProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
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
	// First call raced ahead of refreshLoop's initial fetch (started
	// asynchronously in New) — do one synchronous attempt instead of
	// blocking the caller on the loop's own timing.
	res, err := p.callAPI(ctx)
	if err != nil {
		var deadErr *proxyxoayDeadError
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

// MarkUnhealthyAndRotate forces an immediate new get.php call instead of
// waiting for the next scheduled refresh — this IS proxyxoay's own rotate
// mechanism (calling get.php again is how the vendor hands back a fresh
// exit IP), so a caller-detected failure (ElevenLabs 401 flag) gets a new
// identity right away rather than waiting up to the next scheduled refresh.
// A cooldown rejection here just means the vendor will not hand back a
// DIFFERENT IP yet — not an error worth failing the caller over — so this
// falls back to the still-valid current lease instead of propagating it,
// same as VPN providers do not fail a lease just because rotation itself
// is temporarily unavailable.
func (p *ProxyxoayKeyProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, kind FailureKind, emit func(string)) (Lease, error) {
	if emit == nil {
		emit = func(string) {}
	}
	p.mu.Lock()
	if p.current.URL != "" && p.current.Generation != oldLease.Generation {
		// Someone else already rotated past oldLease — reuse it, do not
		// call the vendor again for nothing.
		cur := p.current
		p.mu.Unlock()
		return cur, nil
	}
	p.mu.Unlock()

	emit("Đang đổi địa chỉ mạng…")
	res, err := p.callAPI(ctx)
	if err != nil {
		var cooldown *proxyxoayCooldownError
		var deadErr *proxyxoayDeadError
		p.mu.Lock()
		p.lastErr = err.Error()
		p.dead = p.dead || errors.As(err, &deadErr)
		cur := p.current
		p.mu.Unlock()
		if errors.As(err, &cooldown) && cur.URL != "" {
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

// Release is a no-op: no persistent tunnel to close (see doc comment above)
// and the refresh loop keeps running for the process lifetime, same
// convention as SharedCurrentProvider.Release.
func (p *ProxyxoayKeyProvider) Release(workerID int, lease Lease) {}
