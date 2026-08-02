-- Migration 019: BỎ cơ chế tự nghỉ sau N lần dùng (migration 018).
-- Thử thực tế: tự nghỉ sau 5 lần không hiệu quả — chuyển lại sang chỉ ban
-- KHI SITE THẬT SỰ CHẶN IP (client release với banned=true → release_proxy_lease
-- cooldown luỹ tiến của migration 017). proxyxoay vẫn không bị ban (017).
--
-- Việc làm:
--   1. Viết lại pick_and_lease_proxy KHÔNG đụng use_count / không tự set banned_until.
--   2. Gỡ ngay các banned_until đang khoá do self-ban 018 (ban_count=0 và
--      last_banned_at IS NULL — đặc trưng self-ban, khác site-ban có ban_count>=1).
--
-- Chạy trong Supabase SQL editor SAU 018_webshare_preemptive_rotation.sql.

DROP FUNCTION IF EXISTS pick_and_lease_proxy(text, text, integer, integer, integer, integer);
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
       CASE COALESCE(source, 'legacy')
         WHEN 'webshare'  THEN 0
         WHEN 'proxyxoay' THEN 1
         ELSE 2
       END ASC,
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
  'Lease proxy; ưu tiên webshare > proxyxoay > legacy; chỉ né IP đang banned_until (ban thật từ site, không tự nghỉ theo số lần dùng).';

-- Gỡ self-ban còn treo từ 018: không có ban_count/last_banned_at (site ban luôn ghi 2 cột này).
UPDATE proxies
   SET banned_until = NULL,
       use_count    = 0
 WHERE source = 'webshare'
   AND banned_until IS NOT NULL
   AND banned_until > NOW()
   AND COALESCE(ban_count, 0) = 0
   AND last_banned_at IS NULL;
