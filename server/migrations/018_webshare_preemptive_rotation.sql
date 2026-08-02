-- Migration 018: chủ động rotate proxy webshare SAU MỘT SỐ LẦN DÙNG NHẤT
-- ĐỊNH, thay vì đợi site đích tự phát hiện và ban (~10 lần) rồi mới xử lý bị
-- động (release_proxy_lease banned=true). Theo yêu cầu: cho chạy tối đa ~5
-- lần rồi tự nghỉ 1 ngày, lặp lại vô hạn — an toàn hơn vì luôn dừng TRƯỚC khi
-- chạm ngưỡng ban thật của site (10 lần), không bao giờ tự loại khỏi pool
-- (giống tinh thần migration 017).
--
-- Cơ chế: thêm cột use_count đếm số lần 1 dòng webshare được LEASE (coi mỗi
-- lần lease ~ 1 lần dùng — đơn giản, không cần client báo cáo gì thêm). Mỗi
-- khi lease đưa use_count chạm ngưỡng p_webshare_max_uses (mặc định 5):
--   - Set banned_until = NOW() + p_webshare_self_ban_minutes (mặc định 1440
--     = 1 ngày) NGAY lúc cấp lease đó — client vẫn được dùng bình thường cho
--     lần thứ 5 này, chỉ là sau khi trả lease lại thì dòng này vào cooldown.
--   - Reset use_count về 0 để đếm lại chu kỳ tiếp theo.
-- Chỉ áp dụng cho source='webshare' — proxyxoay/legacy giữ nguyên cơ chế cũ
-- (proxyxoay tự đổi IP mỗi lần lease nên không cần; legacy gần như đã bỏ).
--
-- Chạy trong Supabase SQL editor SAU 017_escalating_ban_cooldown.sql.

ALTER TABLE proxies ADD COLUMN IF NOT EXISTS use_count INT NOT NULL DEFAULT 0;

DROP FUNCTION IF EXISTS pick_and_lease_proxy(text, text, integer, integer);

CREATE OR REPLACE FUNCTION pick_and_lease_proxy(
  p_session_id                TEXT,
  p_exclude_url                TEXT DEFAULT NULL,
  p_zombie_after               INT  DEFAULT 90,
  p_max_leases                 INT  DEFAULT 2,
  p_webshare_max_uses          INT  DEFAULT 5,
  p_webshare_self_ban_minutes  INT  DEFAULT 1440
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
       SET leased_by    = p_session_id,
           leased_at    = NOW(),
           lease_token  = gen_random_uuid(),
           use_count    = CASE
                             WHEN source = 'webshare' AND COALESCE(use_count, 0) + 1 >= p_webshare_max_uses THEN 0
                             WHEN source = 'webshare' THEN COALESCE(use_count, 0) + 1
                             ELSE use_count
                           END,
           banned_until = CASE
                             WHEN source = 'webshare' AND COALESCE(use_count, 0) + 1 >= p_webshare_max_uses
                               THEN NOW() + (GREATEST(p_webshare_self_ban_minutes, 1) || ' minutes')::interval
                             ELSE banned_until
                           END
     WHERE id = v_id
     RETURNING *;
END;
$$;

COMMENT ON FUNCTION pick_and_lease_proxy(text, text, integer, integer, integer, integer) IS
  'Lease proxy; ưu tiên webshare > proxyxoay > legacy; webshare tự nghỉ p_webshare_self_ban_minutes phút sau mỗi p_webshare_max_uses lần dùng — chủ động rotate trước khi site kịp tự ban.';
