-- ElevenFlow: hạn gói proxy (package) + kiểm tra API; lease chỉ lấy row còn hạn.
-- Chạy sau 004 (hoặc 003 nếu chưa có 004 — nếu chỉ có 003, thay thân hàm bên dưới
-- bằng bản có điều kiện cooldown 60s như trong 003).
--
-- Cột:
--   package_expires_at — NULL = proxy cũ (không khóa theo ngày); có giá trị = sau mốc này không lease.
--   last_api_check_* — kết quả lần «Recheck» gần nhất từ admin.

ALTER TABLE public.proxies
  ADD COLUMN IF NOT EXISTS package_expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_api_check_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_api_check_ok BOOLEAN,
  ADD COLUMN IF NOT EXISTS last_api_check_msg TEXT;

COMMENT ON COLUMN public.proxies.package_expires_at IS 'Hết hạn gói proxy (vd. +30 ngày khi admin thêm); NULL = không áp hạn theo ngày.';
COMMENT ON COLUMN public.proxies.last_api_check_at IS 'Admin Recheck: thời điểm gọi API 1ip gần nhất.';

-- Tắt proxy đã quá hạn gói (idempotent).
UPDATE public.proxies
   SET is_active = false
 WHERE package_expires_at IS NOT NULL
   AND package_expires_at <= NOW()
   AND is_active = true;

-- Bản pick giống 004 (không cooldown last_rotated) + lọc package_expires_at.
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
     AND (
       p_exclude_url IS NULL
       OR ('http://'  || username || ':' || password || '@' || http_host  || ':' || http_port )  != p_exclude_url
     )
     ORDER BY COALESCE(last_rotated_at, '1970-01-01'::timestamptz) ASC
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
  'Lease proxy; bỏ qua row có package_expires_at <= now().';

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
    AND leased_by IS NULL
    AND (package_expires_at IS NULL OR package_expires_at > NOW());
$$;
