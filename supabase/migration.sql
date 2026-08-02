-- ElevenFlow: Supabase Migration
-- Chạy trong Supabase SQL Editor

CREATE TABLE IF NOT EXISTS public.proxies (
  id               SERIAL PRIMARY KEY,
  label            TEXT NOT NULL,
  http_host        TEXT NOT NULL,
  http_port        INTEGER NOT NULL,
  socks_host       TEXT NOT NULL,
  socks_port       INTEGER NOT NULL,
  username         TEXT NOT NULL,
  password         TEXT NOT NULL,
  api_key          TEXT NOT NULL,
  app_id           TEXT NOT NULL DEFAULT '1000',
  last_rotated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_active        BOOLEAN NOT NULL DEFAULT TRUE,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  package_expires_at TIMESTAMPTZ,
  last_api_check_at  TIMESTAMPTZ,
  last_api_check_ok  BOOLEAN,
  last_api_check_msg TEXT
);

-- Chỉ service_role mới đọc được (desktop app không kết nối trực tiếp Supabase)
ALTER TABLE public.proxies ENABLE ROW LEVEL SECURITY;
-- Không tạo policy → anon/authenticated không đọc được, chỉ service_role (server Vercel)

-- Seed: 5 gói xoay (đồng bộ với server/migrations/005_reseed_five_rotating_proxies.sql).
DELETE FROM public.proxies;
INSERT INTO public.proxies
  (label, http_host, http_port, socks_host, socks_port, username, password, api_key, app_id, is_active, last_rotated_at)
VALUES
  ('DC-4G-Random-1m', '103.183.114.120', 36173, '103.183.114.120', 35173,
   'o2iem', 'fqy9q', '5dff244774ffba44d94bf1bfd936c009', '1000', true, '2020-01-01T00:00:00Z'),
  ('Residential-USA-1m', '103.15.95.251', 36654, '103.15.95.251', 35654,
   'z4w6k', 'rtriw', '38c3b34f6eb07cc6a49a9ebc84eba408', '1000', true, '2020-01-01T00:00:00Z'),
  ('Rotate-EU-1m', '103.170.255.148', 36271, '103.170.255.148', 35271,
   'uu6ol', 'n0rnl', 'b2a5c68e6ee569f0967d0a2863e4e9fa', '1000', true, '2020-01-01T00:00:00Z'),
  ('DC-VN-1m', '103.170.254.86', 36315, '103.170.254.86', 35315,
   '7xvvo', 'vdkey', 'b665cca0e5c94cd6841513bc129f6f76', '1000', true, '2020-01-01T00:00:00Z'),
  ('DC-USA-1m', '103.15.95.251', 36021, '103.15.95.251', 35021,
   'lovuk', '81wk3', 'fd5101f2b2ff2fe57aa872f82a885645', '1000', true, '2020-01-01T00:00:00Z');

-- Commercial (JWT + device): chạy thêm ../server/migrations/006_commercial_devices.sql sau khi bật Supabase Auth.

