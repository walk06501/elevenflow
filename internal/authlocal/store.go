// Package authlocal lưu phiên đăng nhập commercial (AES-256-GCM, key gắn device fingerprint).
package authlocal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"elevenflow/internal/proxyserver"
)

type Store struct {
	deviceFP string
	path     string
}

func New(deviceFP string) *Store {
	dir, _ := os.UserConfigDir()
	p := filepath.Join(dir, "ElevenFlow", "session.blob")
	return &Store{deviceFP: deviceFP, path: p}
}

type diskPayload struct {
	Access  string `json:"a"`
	Refresh string `json:"r"`
	Expires int64  `json:"e"`
	Email   string `json:"m"`
}

func (s *Store) key() [32]byte {
	return sha256.Sum256([]byte("elevenflow-sess-v1|" + s.deviceFP))
}

func (s *Store) encrypt(plain []byte) ([]byte, error) {
	k := s.key()
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

func (s *Store) decrypt(blob []byte) ([]byte, error) {
	k := s.key()
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
		return nil, errors.New("session corrupt")
	}
	nonce, ct := blob[:ns], blob[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}

// Save ghi snapshot JWT từ client (đã ApplyCommercialSession).
func (s *Store) Save(client *proxyserver.Client) error {
	ac, ref, exp, email, ok := client.SessionSnapshot()
	if !ok {
		return s.Clear()
	}
	js, err := json.Marshal(diskPayload{Access: ac, Refresh: ref, Expires: exp, Email: email})
	if err != nil {
		return err
	}
	out, err := s.encrypt(js)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Clear xóa file phiên.
func (s *Store) Clear() error {
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// LoadInto đọc file → ApplyCommercialSession (expires tuyệt đối trên đĩa → quy đổi còn lại giây).
func (s *Store) LoadInto(client *proxyserver.Client) error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	plain, err := s.decrypt(raw)
	if err != nil {
		_ = s.Clear()
		return fmt.Errorf("phiên lưu hỏng: %w", err)
	}
	var p diskPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		_ = s.Clear()
		return err
	}
	if p.Access == "" {
		return nil
	}
	remaining := int(p.Expires - time.Now().Unix())
	if remaining < 1 {
		remaining = 1
	}
	client.ApplyCommercialSession(p.Access, p.Refresh, remaining, p.Email)
	return nil
}
