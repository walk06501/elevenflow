-- Migration 002: chuyển từ "shared current proxy" sang "lease per session".
--
-- Mục đích: tránh 2 user cầm chung 1 proxy key tại cùng 1 thời điểm. Mỗi
-- desktop app sinh session_id (UUID, không persist), gọi /api/proxy/lease →
-- server atomic-update proxy free → trả URL cho ĐÚNG session đó. User khác
-- gọi lease cùng lúc sẽ nhận key khác hoặc countdown.
--
-- Run trong Supabase SQL editor:

ALTER TABLE proxies ADD COLUMN IF NOT EXISTS leased_by   TEXT;
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS leased_at   TIMESTAMPTZ;
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS lease_token UUID;

-- Index hỗ trợ pickFreeProxy (WHERE leased_by IS NULL AND last_rotated_at <
-- now() - 60s, ORDER BY last_rotated_at ASC) — tránh full scan khi pool >
-- vài chục key.
CREATE INDEX IF NOT EXISTS idx_proxies_free_lru
  ON proxies (last_rotated_at ASC)
  WHERE leased_by IS NULL AND is_active = true;

-- Index tra lease_token (release) + zombie cleanup (leased_at).
CREATE INDEX IF NOT EXISTS idx_proxies_lease_token ON proxies (lease_token)
  WHERE lease_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_proxies_leased_at   ON proxies (leased_at)
  WHERE leased_by IS NOT NULL;

-- RPC atomic lease: tìm 1 proxy thỏa điều kiện free + đã hết cooldown 60s,
-- claim cho session, trả về row. Dùng SELECT … FOR UPDATE SKIP LOCKED để
-- 2 client đồng thời không dính cùng row (PostgreSQL row-level lock).
--
-- Tham số:
--   p_session_id   text   — session_id của caller
--   p_exclude_url  text   — URL vừa bị ban (NULL nếu lần đầu lease)
--   p_zombie_after int    — giây không heartbeat → coi là zombie, release
--
-- Trả về: row proxies hoặc 0 row nếu hết slot.
CREATE OR REPLACE FUNCTION pick_and_lease_proxy(
  p_session_id   TEXT,
  p_exclude_url  TEXT DEFAULT NULL,
  p_zombie_after INT  DEFAULT 90
)
RETURNS SETOF proxies
LANGUAGE plpgsql
AS $$
DECLARE
  v_id INT;
BEGIN
  -- Lazy cleanup zombie leases (client crash, mạng đứt) — bất cứ ai gọi
  -- pick_and_lease_proxy đều làm hộ. Cheap nếu không có zombie (no-op
  -- update nhờ index leased_at WHERE leased_by NOT NULL).
  UPDATE proxies
     SET leased_by = NULL, leased_at = NULL, lease_token = NULL
   WHERE leased_by IS NOT NULL
     AND leased_at < (NOW() - (p_zombie_after || ' seconds')::interval);

  -- Atomic pick: free + qua cooldown 60s + URL khác excluded.
  -- last_rotated_at + 60s là thời điểm 1ip.vn cho rotate lại; trước đó
  -- gọi changeIP sẽ trả "wait", lãng phí round-trip.
  SELECT id INTO v_id
    FROM proxies
   WHERE is_active = true
     AND leased_by IS NULL
     AND (last_rotated_at IS NULL OR last_rotated_at < NOW() - INTERVAL '60 seconds')
     AND (
       p_exclude_url IS NULL
       OR ('http://'  || username || ':' || password || '@' || http_host  || ':' || http_port )  != p_exclude_url
     )
     ORDER BY COALESCE(last_rotated_at, '1970-01-01'::timestamptz) ASC
     LIMIT 1
     FOR UPDATE SKIP LOCKED;

  IF v_id IS NULL THEN
    RETURN; -- 0 row — caller sẽ trả wait với countdown
  END IF;

  RETURN QUERY
    UPDATE proxies
       SET leased_by   = p_session_id,
           leased_at   = NOW(),
           lease_token = gen_random_uuid()
     WHERE id = v_id
     RETURNING *;
END;
$$;

-- Trả thời gian ngắn nhất cho đến khi có proxy lease lại được — dùng cho
-- countdown khi pick_and_lease_proxy trả 0 row.
CREATE OR REPLACE FUNCTION next_lease_eta_seconds()
RETURNS INT
LANGUAGE sql
AS $$
  SELECT GREATEST(
    1,
    COALESCE(
      EXTRACT(EPOCH FROM (
        MIN(last_rotated_at) + INTERVAL '60 seconds' - NOW()
      ))::INT,
      60
    )
  )
  FROM proxies
  WHERE is_active = true
    AND leased_by IS NULL;  -- key đang free nhưng còn cooldown
$$;
