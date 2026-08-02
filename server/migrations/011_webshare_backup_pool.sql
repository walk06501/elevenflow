-- Migration 011: Webshare làm NGUỒN PROXY DỰ PHÒNG, chạy song song với 1ip.vn.
--
-- Bối cảnh: gói 1ip.vn hiện đang die nhưng vẫn có khả năng sống lại, nên KHÔNG
-- xoá / khoá các dòng cũ. Thêm khả năng đồng bộ định kỳ danh sách Webshare
-- (source='webshare') vào CHUNG bảng proxies — pool app dùng tự động gồm cả
-- hai nguồn, tăng số proxy khả dụng để chịu tải 5-10 người dùng đồng thời.
--
-- Webshare (direct mode) không có API "đổi IP theo request" như 1ip — mỗi
-- dòng là 1 IP:port cố định; HTTP & SOCKS5 dùng CÙNG host:port (theo tài liệu
-- Webshare direct connection). Do đó các dòng source='webshare' có
-- api_key = '' → server (proxyLease/proxyRotate) tự bỏ qua bước gọi 1ip.vn
-- changeip cho các dòng này (nhanh hơn, đỡ 1 round-trip), và hàm pick dưới
-- đây bỏ luôn cooldown 60s cho các dòng này (cooldown 60s chỉ có ý nghĩa với
-- key 1ip cần giãn cách sau đổi IP) → lease/xoay IP nhanh nhất có thể.
--
-- Chạy trong Supabase SQL editor SAU 010_proxies_package_expiry.sql.

ALTER TABLE public.proxies
  ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'legacy',
  ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;

COMMENT ON COLUMN public.proxies.source IS
  'legacy = gói 1ip.vn (đổi IP qua changeip, có cooldown 60s); webshare = đồng bộ từ Webshare API (không changeip, không cooldown, tối ưu tốc độ).';
COMMENT ON COLUMN public.proxies.last_seen_at IS
  'Lần gần nhất đồng bộ Webshare còn thấy dòng này trong list tải về — dùng để tắt (is_active=false) khi nhà cung cấp đã thay IP khác.';

-- api_key/app_id rỗng hợp lệ cho dòng webshare (không dùng changeip).
ALTER TABLE public.proxies ALTER COLUMN api_key SET DEFAULT '';
ALTER TABLE public.proxies ALTER COLUMN api_key DROP NOT NULL;
ALTER TABLE public.proxies ALTER COLUMN app_id SET DEFAULT '';
ALTER TABLE public.proxies ALTER COLUMN app_id DROP NOT NULL;
UPDATE public.proxies SET api_key = '' WHERE api_key IS NULL;
UPDATE public.proxies SET app_id  = '' WHERE app_id  IS NULL;

-- Khoá unique (host, port, username) để đồng bộ dùng upsert — không insert
-- trùng khi IP không đổi giữa 2 lần sync liên tiếp.
CREATE UNIQUE INDEX IF NOT EXISTS idx_proxies_host_port_user
  ON public.proxies (http_host, http_port, username);

-- pick_and_lease_proxy bản "nhanh": dòng KHÔNG có api_key (webshare) bỏ qua
-- điều kiện cooldown 60s (chỉ cần free + chưa hết hạn gói) → lease gần như
-- ngay lập tức. Dòng có api_key thật (1ip) vẫn giữ cooldown 60s như cũ.
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
       COALESCE(api_key, '') = ''
       OR last_rotated_at IS NULL
       OR last_rotated_at < NOW() - INTERVAL '60 seconds'
     )
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
  'Lease proxy; bỏ cooldown 60s cho dòng api_key rỗng (webshare, không changeip) để xoay IP nhanh nhất.';

CREATE OR REPLACE FUNCTION next_lease_eta_seconds()
RETURNS INT
LANGUAGE sql
AS $$
  SELECT GREATEST(
    1,
    COALESCE(
      MIN(
        CASE
          WHEN COALESCE(api_key, '') = '' THEN 1
          WHEN last_rotated_at IS NULL THEN 1
          ELSE EXTRACT(EPOCH FROM (last_rotated_at + INTERVAL '60 seconds' - NOW()))::INT
        END
      ),
      60
    )
  )
  FROM proxies
  WHERE is_active = true
    AND leased_by IS NULL
    AND (package_expires_at IS NULL OR package_expires_at > NOW());
$$;
