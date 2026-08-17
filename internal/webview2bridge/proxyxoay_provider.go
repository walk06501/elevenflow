package webview2bridge

import (
	"context"
	"encoding/json"
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

// callAPI does one GET to proxyxoay.shop and classifies the result:
// ok=true on status 100, dead=true on 101/102 (permanent), otherwise a
// transient error the caller should just retry later.
func (p *ProxyxoayKeyProvider) callAPI(ctx context.Context) (httpURL string, dead bool, err error) {
	u := fmt.Sprintf(
		"%s?key=%s&nhamang=random&tinhthanh=0&whitelist=%s",
		proxyxoayBaseURL, url.QueryEscape(p.apiKey), url.QueryEscape(p.whitelist),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", false, err
	}
	client := &http.Client{Timeout: proxyxoayHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("proxyxoay unreachable: %w", err)
	}
	defer resp.Body.Close()

	var data proxyxoayAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", false, fmt.Errorf("proxyxoay invalid response: %w", err)
	}
	msg := data.Message
	if msg == "" {
		msg = data.Comen
	}

	switch data.Status {
	case 100:
		host, port, ok := parseHostPort(data.ProxyHTTP)
		if !ok {
			return "", false, fmt.Errorf("proxyxoay: response missing usable proxyhttp (%q)", data.ProxyHTTP)
		}
		return fmt.Sprintf("http://%s:%d", host, port), false, nil
	case 101, 102:
		if msg == "" {
			msg = fmt.Sprintf("status=%d", data.Status)
		}
		return "", true, fmt.Errorf("proxyxoay key dead: %s", msg)
	default:
		if msg == "" {
			msg = fmt.Sprintf("status=%d", data.Status)
		}
		return "", false, fmt.Errorf("proxyxoay transient: %s", msg)
	}
}

var proxyxoayTTLPattern = regexp.MustCompile(`(\d+)\s*s\b`)

// refreshLoop calls the API once immediately, then every
// proxyxoayRefreshInterval — well before the vendor's own session TTL — so
// an already-running WebView2 session's configured proxy stays valid across
// long sessions without every caller having to know about the vendor's
// timer. dead keys are retried on the same cadence (in case the operator
// tops up credit) rather than stopping forever, since there is no DB row
// here to delete like the Vercel relay's admin flow does.
func (p *ProxyxoayKeyProvider) refreshLoop() {
	p.refreshOnce(context.Background())
	t := time.NewTicker(proxyxoayRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.refreshOnce(context.Background())
		}
	}
}

func (p *ProxyxoayKeyProvider) refreshOnce(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, proxyxoayHTTPTimeout+5*time.Second)
	defer cancel()
	url, dead, err := p.callAPI(ctx)

	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.lastErr = err.Error()
		if dead && !p.dead {
			log.Printf("[proxyxoay] %s: key marked dead: %v", p.name, err)
		}
		p.dead = p.dead || dead
		return
	}
	p.dead = false
	p.lastErr = ""
	if p.current.URL != url {
		p.generation++
		p.current = Lease{URL: url, AcquiredAt: time.Now(), Generation: p.generation}
		log.Printf("[proxyxoay] %s: proxy ready (%s)", p.name, redactProxyxoayURL(url))
	}
}

func redactProxyxoayURL(u string) string {
	// No credentials embedded (auth is IP-whitelist/session-based), so there
	// is nothing sensitive to strip — kept as its own function anyway so a
	// future format change with embedded creds does not leak into logs by
	// accident without someone having to remember to add this.
	return u
}

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
	url, dead, err := p.callAPI(ctx)
	if err != nil {
		p.mu.Lock()
		p.lastErr = err.Error()
		p.dead = p.dead || dead
		p.mu.Unlock()
		return Lease{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current.URL == "" {
		p.generation++
		p.current = Lease{URL: url, AcquiredAt: time.Now(), Generation: p.generation}
	}
	return p.current, nil
}

// MarkUnhealthyAndRotate forces an immediate new get.php call instead of
// waiting for the next scheduled refresh — this IS proxyxoay's own rotate
// mechanism (calling get.php again is how the vendor hands back a fresh
// exit IP), so a caller-detected failure (ElevenLabs 401 flag) gets a new
// identity right away rather than waiting up to proxyxoayRefreshInterval.
func (p *ProxyxoayKeyProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
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
	url, dead, err := p.callAPI(ctx)
	if err != nil {
		p.mu.Lock()
		p.lastErr = err.Error()
		p.dead = p.dead || dead
		p.mu.Unlock()
		return Lease{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dead = false
	p.lastErr = ""
	p.generation++
	p.current = Lease{URL: url, AcquiredAt: time.Now(), Generation: p.generation}
	return p.current, nil
}

// Release is a no-op: no persistent tunnel to close (see doc comment above)
// and the refresh loop keeps running for the process lifetime, same
// convention as SharedCurrentProvider.Release.
func (p *ProxyxoayKeyProvider) Release(workerID int, lease Lease) {}
