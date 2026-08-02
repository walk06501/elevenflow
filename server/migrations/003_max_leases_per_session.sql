-- Migration 003: giới hạn số proxy đồng thời / session (tránh 1 user chiếm hết pool).
--
-- Chạy sau 002. Thêm tham số p_max_leases (mặc định 2) + advisory lock theo
-- session để 2 goroutine cùng session không vượt cap khi race.
--
-- QUAN TRỌNG: Phải DROP bản 002 (3 tham số) trước. CREATE OR REPLACE với thêm
-- tham số tạo OVERLOAD mới — không xóa hàm cũ → Postgres báo lỗi "function
-- name is not unique" khi COMMENT / khi Supabase gọi RPC không rõ overload.

DROP FUNCTION IF EXISTS pick_and_lease_proxy(text, text, integer);

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
  -- Serialize mọi lease request của cùng 1 session → đếm + pick không bị
  -- race (2 goroutine cùng thấy count=1 rồi cả 2 pick row khác nhau → 3 lease).
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
     AND (last_rotated_at IS NULL OR last_rotated_at < NOW() - INTERVAL '60 seconds')
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
  'Lease 1 proxy row for session. Max p_max_leases concurrent rows per session_id. Uses advisory lock per session.';
