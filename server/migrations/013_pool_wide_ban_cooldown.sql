-- Migration 013: cơ chế "ban" hiện tại CHỈ có tác dụng cục bộ (excludeUrl cho
-- đúng request kế tiếp của CÙNG session) — session/luồng KHÁC vẫn có thể được
-- cấp lại NGAY chính IP vừa bị site ban, vì server chưa từng lưu trạng thái
-- "IP này vừa bị ban" ở mức pool. proxyRelease.ts nhận body.banned từ app
-- nhưng chưa từng truyền xuống DB — coi như bỏ đi. Migration này vá lỗ hổng:
--
-- 1) banned_until: khi 1 lease release với banned=true → toàn bộ pool (mọi
--    session khác) đều tránh IP đó trong p_ban_cooldown_minutes phút, không
--    chỉ session vừa gặp ban. Áp dụng chung cho cả legacy và webshare.
-- 2) ban_count / last_banned_at: đếm số lần bị ban gần đây (rơi ra khỏi cửa
--    sổ 24h thì tính lại từ 1) — bị ban liên tục ≥ p_max_strikes trong 24h
--    → tự động is_active=false ("nghỉ hưu" IP hay bị chặn, không tốn slot
--    pool + không tốn lượt xoay vô ích).
-- 3) upsert_webshare_proxies: sync lại KHÔNG bật lại is_active cho IP đã
--    "nghỉ hưu" vì ban (chỉ bật lại IP tắt do tạm vắng mặt trong 1 kỳ sync).
--
-- Chạy trong Supabase SQL editor SAU 012_webshare_priority_and_fast_upsert.sql.

ALTER TABLE public.proxies
  ADD COLUMN IF NOT EXISTS banned_until   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS ban_count      INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_banned_at TIMESTAMPTZ;

COMMENT ON COLUMN public.proxies.banned_until IS
  'Site đích vừa chặn IP này → không session nào được lease lại trước mốc này (pool-wide, khác excludeUrl chỉ có hiệu lực 1 request).';
COMMENT ON COLUMN public.proxies.ban_count IS
  'Số lần bị ban gần đây (cửa sổ trượt 24h kể từ last_banned_at) — vượt ngưỡng → tự tắt is_active.';

CREATE INDEX IF NOT EXISTS idx_proxies_banned_until ON public.proxies (banned_until)
  WHERE banned_until IS NOT NULL;

-- pick_and_lease_proxy: thêm điều kiện tránh IP đang trong thời gian "nghỉ" vì ban.
DROP FUNCTION IF EXISTS pick_and_lease_proxy(text, text, integer, integer);

CREATE OR REPLACE FUNCTION pick_and_lease_proxy(
  p_session_id   TEXT,
  p_exclude_url  TEXT DEFAULT NULL,
  p_zombie_after INT  DEFAULT 90,
  p_max_leases   INT  DEFAULT 2
)
RETURNS SETOF proxies
LANGUAGE plpgsql
AS $$
DECLARE
  v_id INT;
  v_cnt INT;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext(p_session_id)::bigint);

  UPDATE proxies
     SET leased_by = NULL, leased_at = NULL, lease_token = NULL
   WHERE leased_by IS NOT NULL
     AND leased_at < (NOW() - (p_zombie_after || ' seconds')::interval);

  SELECT COUNT(*)::INT INTO v_cnt FROM proxies WHERE leased_by = p_session_id;
  IF v_cnt >= p_max_leases THEN
    RETURN;
  END IF;

  SELECT id INTO v_id
    FROM proxies
   WHERE is_active = true
     AND leased_by IS NULL
     AND (package_expires_at IS NULL OR package_expires_at > NOW())
     AND (banned_until IS NULL OR banned_until <= NOW())
     AND (
       COALESCE(api_key, '') = ''
       OR last_rotated_at IS NULL
       OR last_rotated_at < NOW() - INTERVAL '60 seconds'
     )
     AND (
       p_exclude_url IS NULL
       OR ('http://'  || username || ':' || password || '@' || http_host  || ':' || http_port )  != p_exclude_url
     )
     ORDER BY
       (COALESCE(api_key, '') <> '') ASC,
       COALESCE(last_rotated_at, '1970-01-01'::timestamptz) ASC
     LIMIT 1
     FOR UPDATE SKIP LOCKED;

  IF v_id IS NULL THEN
    RETURN;
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

COMMENT ON FUNCTION pick_and_lease_proxy(text, text, integer, integer) IS
  'Lease proxy; ưu tiên webshare trước legacy; loại IP đang cooldown vì bị ban (banned_until).';

-- ETA cũng phải né banned_until (không báo "sắp có" khi chỉ còn IP đang bị ban).
CREATE OR REPLACE FUNCTION next_lease_eta_seconds()
RETURNS INT
LANGUAGE sql
AS $$
  SELECT GREATEST(
    1,
    COALESCE(
      MIN(
        GREATEST(
          CASE
            WHEN COALESCE(api_key, '') = '' THEN 1
            WHEN last_rotated_at IS NULL THEN 1
            ELSE EXTRACT(EPOCH FROM (last_rotated_at + INTERVAL '60 seconds' - NOW()))::INT
          END,
          CASE
            WHEN banned_until IS NULL THEN 1
            ELSE EXTRACT(EPOCH FROM (banned_until - NOW()))::INT
          END
        )
      ),
      60
    )
  )
  FROM proxies
  WHERE is_active = true
    AND leased_by IS NULL
    AND (package_expires_at IS NULL OR package_expires_at > NOW());
$$;

-- release_proxy_lease: RPC atomic cho POST /api/proxy/release. banned=true →
-- áp cooldown pool-wide + tăng ban_count (reset nếu lần ban trước đã > 24h) +
-- tự tắt is_active khi vượt ngưỡng p_max_strikes trong 24h.
CREATE OR REPLACE FUNCTION release_proxy_lease(
  p_session_id        TEXT,
  p_lease_token        UUID,
  p_banned             BOOLEAN DEFAULT false,
  p_cooldown_minutes   INT     DEFAULT 10,
  p_max_strikes        INT     DEFAULT 3
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
  v_id INT;
  v_new_ban_count INT;
BEGIN
  IF NOT p_banned THEN
    UPDATE proxies
       SET leased_by = NULL, leased_at = NULL, lease_token = NULL
     WHERE lease_token = p_lease_token
       AND leased_by = p_session_id;
    RETURN;
  END IF;

  UPDATE proxies
     SET leased_by      = NULL,
         leased_at      = NULL,
         lease_token    = NULL,
         ban_count      = CASE
           WHEN last_banned_at IS NOT NULL AND last_banned_at > NOW() - INTERVAL '24 hours'
             THEN COALESCE(ban_count, 0) + 1
           ELSE 1
         END,
         last_banned_at = NOW(),
         banned_until   = NOW() + (GREATEST(p_cooldown_minutes, 1) || ' minutes')::interval
   WHERE lease_token = p_lease_token
     AND leased_by = p_session_id
  RETURNING id, ban_count INTO v_id, v_new_ban_count;

  IF v_id IS NOT NULL AND v_new_ban_count >= p_max_strikes THEN
    UPDATE proxies SET is_active = false WHERE id = v_id;
  END IF;
END;
$$;

COMMENT ON FUNCTION release_proxy_lease(text, uuid, boolean, integer, integer) IS
  'Release lease; banned=true áp cooldown pool-wide (mọi session tránh IP này) + tự tắt is_active nếu bị ban lặp lại (>= p_max_strikes trong 24h).';

-- upsert_webshare_proxies: KHÔNG bật lại is_active cho IP đã "nghỉ hưu" vì bị
-- ban lặp lại (ban_count đã chạm ngưỡng) — chỉ bật lại IP tắt do tạm vắng mặt
-- ở kỳ sync trước. Webshare không biết IP có đang bị site đích chặn hay không
-- nên không thể tự quyết định bật lại các IP này.
CREATE OR REPLACE FUNCTION upsert_webshare_proxies(p_rows JSONB)
RETURNS INT
LANGUAGE plpgsql
AS $$
DECLARE
  v_count INT;
BEGIN
  WITH incoming AS (
    SELECT
      (r->>'host')::text     AS http_host,
      (r->>'port')::int      AS http_port,
      (r->>'username')::text AS username,
      (r->>'password')::text AS password,
      (r->>'label')::text    AS label
    FROM jsonb_array_elements(p_rows) AS r
  ),
  up AS (
    INSERT INTO proxies (
      label, http_host, http_port, socks_host, socks_port,
      username, password, api_key, app_id, is_active, source,
      last_seen_at, last_rotated_at
    )
    SELECT
      label, http_host, http_port, http_host, http_port,
      username, password, '', '', true, 'webshare',
      NOW(), '1970-01-01T00:00:00Z'::timestamptz
    FROM incoming
    ON CONFLICT (http_host, http_port, username)
    DO UPDATE SET
      password     = EXCLUDED.password,
      is_active    = (COALESCE(proxies.ban_count, 0) < 3),
      last_seen_at = NOW()
      -- last_rotated_at KHÔNG update ở nhánh conflict — giữ nguyên LRU/cooldown hiện tại.
    RETURNING 1
  )
  SELECT COUNT(*) INTO v_count FROM up;
  RETURN v_count;
END;
$$;

COMMENT ON FUNCTION upsert_webshare_proxies(jsonb) IS
  'Bulk upsert Webshare; không tự bật lại IP đã bị tắt vì ban lặp lại (ban_count>=3), chỉ bật lại IP tắt do tạm vắng mặt.';
