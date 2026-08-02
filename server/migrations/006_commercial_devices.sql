-- Migration 006: thiết bị đã cấp phép (commercial / JWT + X-Device-ID).
-- Chạy trong Supabase SQL Editor sau khi đã có auth.users (bật Email auth trong Supabase).
--
-- RLS: không policy public — chỉ service_role (Vercel) truy cập qua supabase-js.

CREATE TABLE IF NOT EXISTS public.licensed_devices (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              UUID NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  device_fingerprint   TEXT NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT licensed_devices_user_device UNIQUE (user_id, device_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_licensed_devices_user ON public.licensed_devices (user_id);

ALTER TABLE public.licensed_devices ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE public.licensed_devices IS
  'Mỗi user tối đa MAX_DEVICES_PER_USER fingerprint; desktop gửi X-Device-ID + Bearer JWT.';
