package proxyserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CommercialQuotaCheck gọi POST /api/commercial/quota-check (commercial + JWT + device).
func (c *Client) CommercialQuotaCheck(ctx context.Context, needChars int64) error {
	if needChars <= 0 {
		return nil
	}
	body, _ := json.Marshal(map[string]int64{"need_chars": needChars})
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.serverURL+"/api/commercial/quota-check",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyAuthHeaders(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("quota-check: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("hết hạn mức ký tự (quota). Liên hệ người cấp phép hoặc chờ admin tăng hạn mức.")
	}
	return fmt.Errorf("quota-check: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
}

// CommercialQuotaSnapshot — JSON từ POST /api/commercial/quota-check (need_chars=0).
type CommercialQuotaSnapshot struct {
	OK         bool  `json:"ok"`
	Unlimited bool  `json:"unlimited"`
	CharsUsed int64 `json:"chars_used"`
	MaxChars  int64 `json:"max_chars"`
	Remaining int64 `json:"remaining"`
}

// CommercialQuotaFetch lấy hạn mức hiện tại (không trừ thêm; need_chars=0).
func (c *Client) CommercialQuotaFetch(ctx context.Context) (CommercialQuotaSnapshot, error) {
	var zero CommercialQuotaSnapshot
	body, _ := json.Marshal(map[string]int64{"need_chars": 0})
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.serverURL+"/api/commercial/quota-check",
		bytes.NewReader(body),
	)
	if err != nil {
		return zero, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyAuthHeaders(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return zero, fmt.Errorf("quota: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("quota: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var snap CommercialQuotaSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return zero, fmt.Errorf("quota: %w", err)
	}
	if !snap.OK {
		return zero, fmt.Errorf("quota: máy chủ từ chối")
	}
	return snap, nil
}

func (c *Client) CommercialConsumeChars(ctx context.Context, chars int64) error {
	if chars <= 0 {
		return nil
	}
	body, _ := json.Marshal(map[string]int64{"chars": chars})
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.serverURL+"/api/commercial/quota-consume",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyAuthHeaders(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("quota-consume: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("quota-consume: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
}
