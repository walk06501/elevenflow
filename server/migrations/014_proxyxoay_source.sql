-- Migration 014: thêm nguồn proxyxoay.shop (backup thứ 2, xoay theo API
-- get.php giống 1ip.vn — khác Webshare vì Webshare không có API đổi IP).
--
-- Độ ưu tiên khi lease (nhanh nhất → chậm nhất theo yêu cầu):
--   1. webshare   — static pool lớn, không gọi API, không cooldown.
--   2. proxyxoay  — gọi API xoay (~1 round-trip), cooldown 60s như 1ip.
--   3. legacy     — 1ip.vn, đang die, ưu tiên thấp nhất (backup cuối, tự
--                    hoạt động lại ngay nếu 1ip.vn sống lại).
--
-- Trước migration này, pick_and_lease_proxy chỉ phân biệt 2 nhóm qua
-- api_key rỗng/không rỗng (webshare vs "còn lại"). proxyxoay CŨNG có
-- api_key nên sẽ bị xếp NGANG legacy nếu không sửa — đổi ORDER BY sang
-- dùng cột `source` trực tiếp cho đúng 3 tier.
--
-- Chạy trong Supabase SQL editor SAU 013_pool_wide_ban_cooldown.sql.

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
  'Lease proxy; ưu tiên webshare > proxyxoay > legacy (cột source); loại IP đang cooldown vì ban (banned_until).';
