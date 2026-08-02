-- Migration 012: sửa 2 vấn đề phát hiện sau khi bật pool Webshare (011):
--
-- 1) BUG tốc độ: cột last_rotated_at có DEFAULT now() ở DB. Khi sync (011)
--    upsert KHÔNG gửi last_rotated_at, Postgres tự điền now() cho dòng mới
--    (không phải NULL như kỳ vọng) → dòng Webshare mới lại có timestamp MỚI
--    HƠN dòng 1ip.vn cũ (đã rotate từ sáng) → pick_and_lease_proxy (ORDER BY
--    last_rotated_at ASC) chọn NHẦM dòng 1ip.vn (đang chết) trước, worker
--    phải chờ hết timeout changeip mới rớt qua dòng khác → chậm.
--    Fix: hàm upsert_webshare_proxies() dưới đây set last_rotated_at
--    ='1970-01-01' CHỈ khi INSERT (dòng mới), giữ nguyên khi UPDATE (dòng cũ).
--
-- 2) Ưu tiên rõ ràng, không phụ thuộc timestamp: pick_and_lease_proxy giờ
--    LUÔN ưu tiên dòng KHÔNG có api_key (Webshare — không tốn round-trip
--    changeip, không cooldown) trước dòng có api_key (1ip.vn — cần gọi API
--    đổi IP có thể timeout/chết). Trong từng nhóm mới xếp theo LRU như cũ.
--    1ip.vn (nếu sống lại) vẫn được dùng làm dự phòng khi Webshare hết chỗ.
--
-- Chạy trong Supabase SQL editor SAU 011_webshare_backup_pool.sql.

-- Data fix một lần: các dòng Webshare đã lỡ bị set last_rotated_at=now() ở
-- lần sync trước (migration 011) → đưa về epoch để không bị coi là "vừa
-- rotate" (ảnh hưởng LRU trong cùng nhóm webshare, dù ORDER BY mới ở dưới
-- đã không còn phụ thuộc việc này để phân biệt legacy/webshare).
UPDATE public.proxies
   SET last_rotated_at = '1970-01-01T00:00:00Z'
 WHERE source = 'webshare';

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
     -- Ưu tiên tuyệt đối: dòng không api_key (webshare, nhanh) trước dòng có
     -- api_key (1ip.vn, cần changeip — có thể timeout nếu vendor die). Trong
     -- từng nhóm, LRU như cũ (rotate lâu nhất trước) để xoay đều cả pool.
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
  'Lease proxy; LUÔN ưu tiên dòng api_key rỗng (webshare, nhanh) trước dòng 1ip.vn (cần changeip, có cooldown 60s).';

-- Bulk upsert cho đồng bộ Webshare — 1 round-trip, xử lý ĐÚNG insert vs
-- update: last_rotated_at chỉ set epoch khi INSERT (dòng mới → lease ngay),
-- KHÔNG đụng khi UPDATE (dòng đã có → giữ nguyên vị trí LRU đang chạy).
-- p_rows: jsonb array [{ "host":"1.2.3.4", "port":9999, "username":"u",
--                        "password":"p", "label":"webshare-1.2.3.4-9999" }, ...]
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
      is_active    = true,
      last_seen_at = NOW()
      -- last_rotated_at KHÔNG update ở nhánh conflict — giữ nguyên LRU/cooldown hiện tại.
    RETURNING 1
  )
  SELECT COUNT(*) INTO v_count FROM up;
  RETURN v_count;
END;
$$;

COMMENT ON FUNCTION upsert_webshare_proxies(jsonb) IS
  'Bulk upsert proxy Webshare 1 round-trip; set last_rotated_at=epoch CHỈ khi insert dòng mới (lease ngay), giữ nguyên khi update dòng cũ.';
