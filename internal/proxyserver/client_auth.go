package proxyserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// PublicConfig — GET /api/config (không cần secret).
type PublicConfig struct {
	CommercialAuth bool `json:"commercialAuth"`
}

// FetchPublicConfig đọc cờ commercial từ server.
func FetchPublicConfig(ctx context.Context, baseURL string) (PublicConfig, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		return PublicConfig{}, fmt.Errorf("empty server URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/config", nil)
	if err != nil {
		return PublicConfig{}, err
	}
	hc := &http.Client{Timeout: 15 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return PublicConfig{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return PublicConfig{}, fmt.Errorf("GET /api/config: HTTP %d", resp.StatusCode)
	}
	var c PublicConfig
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return PublicConfig{}, err
	}
	return c, nil
}

// LoginResult kết quả đăng nhập / refresh.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	UserEmail    string
}

type authJSON struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	User         struct {
		Email string `json:"email"`
	} `json:"user"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

// PasswordLogin POST /api/auth/login (cần X-App-Secret). deviceID — gửi X-Device-ID khi commercial (đăng ký licensed_devices).
func PasswordLogin(ctx context.Context, baseURL, appSecret, email, password, deviceID string) (LoginResult, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return LoginResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Secret", appSecret)
	if strings.TrimSpace(deviceID) != "" {
		req.Header.Set("X-Device-ID", strings.TrimSpace(deviceID))
	}
	hc := &http.Client{Timeout: 45 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return LoginResult{}, err
	}
	defer resp.Body.Close()
	var j authJSON
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return LoginResult{}, err
	}
	if resp.StatusCode != http.StatusOK || j.AccessToken == "" {
		msg := j.Message
		if msg == "" {
			msg = j.Error
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return LoginResult{}, fmt.Errorf("%s", msg)
	}
	return LoginResult{
		AccessToken:  j.AccessToken,
		RefreshToken: j.RefreshToken,
		ExpiresIn:    j.ExpiresIn,
		UserEmail:    j.User.Email,
	}, nil
}

func refreshAccess(ctx context.Context, baseURL, appSecret, refresh, deviceID string) (LoginResult, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	body, _ := json.Marshal(map[string]string{"refresh_token": refresh})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/auth/refresh", bytes.NewReader(body))
	if err != nil {
		return LoginResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Secret", appSecret)
	if strings.TrimSpace(deviceID) != "" {
		req.Header.Set("X-Device-ID", strings.TrimSpace(deviceID))
	}
	hc := &http.Client{Timeout: 45 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return LoginResult{}, err
	}
	defer resp.Body.Close()
	var j authJSON
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return LoginResult{}, err
	}
	if resp.StatusCode != http.StatusOK || j.AccessToken == "" {
		return LoginResult{}, fmt.Errorf("refresh failed")
	}
	return LoginResult{
		AccessToken:  j.AccessToken,
		RefreshToken: j.RefreshToken,
		ExpiresIn:    j.ExpiresIn,
		UserEmail:    j.User.Email,
	}, nil
}
