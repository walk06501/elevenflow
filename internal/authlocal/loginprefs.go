package authlocal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Chỉ lưu email + mật khẩu để điền form nhanh (user vẫn phải bấm Đăng nhập).
// Không lưu JWT / refresh token — tránh đăng nhập lại mà không nhập mật khẩu.

type loginPrefsPayload struct {
	Email    string `json:"e"`
	Password string `json:"p"`
}

func loginPrefsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ElevenFlow", "saved_login.blob"), nil
}

func prefsKey(deviceFP string) [32]byte {
	return sha256.Sum256([]byte("elevenflow-login-prefs-v1|" + deviceFP))
}

func encryptPrefs(deviceFP string, plain []byte) ([]byte, error) {
	k := prefsKey(deviceFP)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plain, nil)...), nil
}

func decryptPrefs(deviceFP string, blob []byte) ([]byte, error) {
	k := prefsKey(deviceFP)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns+16 {
		return nil, errors.New("prefs corrupt")
	}
	nonce, ct := blob[:ns], blob[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}

// SaveLoginPrefs ghi email + mật khẩu (đã mã hóa) — chỉ khi user chủ động chọn ghi nhớ.
func SaveLoginPrefs(deviceFP, email, password string) error {
	p, err := loginPrefsPath()
	if err != nil {
		return err
	}
	js, err := json.Marshal(loginPrefsPayload{Email: email, Password: password})
	if err != nil {
		return err
	}
	out, err := encryptPrefs(deviceFP, js)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// LoadLoginPrefs đọc email + mật khẩu đã lưu; ok=false nếu không có file / lỗi.
func LoadLoginPrefs(deviceFP string) (email, password string, ok bool) {
	p, err := loginPrefsPath()
	if err != nil {
		return "", "", false
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return "", "", false
	}
	plain, err := decryptPrefs(deviceFP, raw)
	if err != nil {
		_ = ClearLoginPrefs()
		return "", "", false
	}
	var pl loginPrefsPayload
	if err := json.Unmarshal(plain, &pl); err != nil {
		_ = ClearLoginPrefs()
		return "", "", false
	}
	if pl.Email == "" && pl.Password == "" {
		return "", "", false
	}
	return pl.Email, pl.Password, true
}

// ClearLoginPrefs xóa file ghi nhớ form.
func ClearLoginPrefs() error {
	p, err := loginPrefsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
