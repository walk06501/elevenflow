-- ElevenFlow: bảng proxies cũ (chỉ host:port) — thêm username/password cho HTTP/SOCKS.
-- Chạy trong Supabase SQL Editor nếu Table Editor không thấy hai cột này.
-- Server build URL: http://user:pass@http_host:http_port và socks5://...@socks_host:socks_port
-- api_key vẫn là package key cho changeip (api.1ip.vn), không thay cho user proxy.

ALTER TABLE public.proxies
  ADD COLUMN IF NOT EXISTS username TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS password TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN public.proxies.username IS 'User đăng nhập proxy (dashboard: cột User/Pass hoặc phần thứ 3 trong dòng Http ip:port:user:pass).';
COMMENT ON COLUMN public.proxies.password IS 'Mật khẩu proxy HTTP/SOCKS (phần thứ 4 trong dòng Http).';
COMMENT ON COLUMN public.proxies.api_key IS 'Api key gói — dùng changeip; khác user/pass proxy.';
