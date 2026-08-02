package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FetchFromRotateAPI gọi GET (URL đầy đủ có key, ví dụ proxyxoay.shop/...get.php?key=...).
// Hỗ trợ JSON có proxyhttp / proxy / data (chuỗi ip:port:user:pass) hoặc body text một dòng.
func FetchFromRotateAPI(ctx context.Context, apiURL string) (httpProxyURL string, rawSnippet string, err error) {
	if strings.TrimSpace(apiURL) == "" {
		return "", "", fmt.Errorf("empty rotate api url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "ElevenFlow/1.0")
	cli := &http.Client{Timeout: 45 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("rotate api http %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}
	raw := strings.TrimSpace(string(body))
	rawSnippet = maskForLog(raw)

	trim := strings.TrimSpace(raw)
	if strings.HasPrefix(trim, "{") {
		var obj map[string]any
		if err := json.Unmarshal(body, &obj); err == nil {
			for _, k := range []string{"proxyhttp", "proxy_http", "proxyHttp", "http", "proxy"} {
				if s, ok := obj[k].(string); ok && strings.TrimSpace(s) != "" {
					u, err := toHTTPProxyURL(strings.TrimSpace(s))
					return u, rawSnippet, err
				}
			}
			if s, ok := obj["data"].(string); ok && strings.TrimSpace(s) != "" {
				u, err := toHTTPProxyURL(strings.TrimSpace(s))
				return u, rawSnippet, err
			}
			if st, ok := obj["status"].(float64); ok && st != 100 {
				msg, _ := obj["message"].(string)
				return "", rawSnippet, fmt.Errorf("api status=%v msg=%s", int(st), msg)
			}
			return "", rawSnippet, fmt.Errorf("json không có trường proxy (proxyhttp/proxy/data)")
		}
	}

	line := strings.Split(raw, "\n")[0]
	line = strings.TrimSpace(line)
	u, err := toHTTPProxyURL(line)
	return u, rawSnippet, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maskForLog(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// toHTTPProxyURL: "host:port:user:pass" -> http://user:pass@host:port ; đã có scheme thì giữ.
func toHTTPProxyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty proxy string")
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return raw, nil
	}
	if strings.Contains(raw, "@") {
		u, err := url.Parse("http://" + raw)
		if err != nil {
			return "", err
		}
		if u.Host == "" {
			return "", fmt.Errorf("invalid host in %q", raw)
		}
		if u.User != nil {
			return "http://" + u.User.String() + "@" + u.Host, nil
		}
		return "http://" + u.Host, nil
	}
	parts := strings.Split(raw, ":")
	if len(parts) == 4 {
		host, port, user, pass := parts[0], parts[1], parts[2], parts[3]
		ui := url.UserPassword(user, pass)
		return fmt.Sprintf("http://%s@%s:%s", ui.String(), host, port), nil
	}
	return "", fmt.Errorf("không parse được proxy: %q (cần host:port:user:pass hoặc URL đầy đủ)", raw)
}
