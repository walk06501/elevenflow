-- Migration 016: tăng ban cooldown mặc định 10 phút → 1 ngày (theo yêu cầu —
-- 10 phút quá ngắn, site đích có thể vẫn "nhớ" IP vừa ban). Đi kèm: nới cửa
-- sổ đếm "bị ban lặp lại" từ cứng 24h → tham số hoá (mặc định 7 ngày), vì
-- nếu cooldown = 24h thì với cửa sổ cũ 24h, 1 IP KHÔNG THỂ bị ban 2 lần
-- trong vòng 24h (đang bị cấm dùng suốt thời gian đó) → tính năng "≥3 lần
-- bị ban thì tự nghỉ hưu" sẽ gần như vô hiệu nếu không nới cửa sổ này ra.
--
-- Giá trị cooldown/strike-window thực tế set qua env Vercel:
--   PROXY_BAN_COOLDOWN_MINUTES=1440       (1 ngày)
--   PROXY_BAN_STRIKE_WINDOW_HOURS=168     (7 ngày)
-- (server/lib/supabase.ts đọc 2 biến này, có default nếu không set).
--
-- Chạy trong Supabase SQL editor SAU 015_remove_legacy_1ip.sql.

DROP FUNCTION IF EXISTS release_proxy_lease(text, uuid, boolean, integer, integer);

CREATE OR REPLACE FUNCTION release_proxy_lease(
  p_session_id          TEXT,
  p_lease_token          UUID,
  p_banned               BOOLEAN DEFAULT false,
  p_cooldown_minutes     INT     DEFAULT 1440,
  p_max_strikes          INT     DEFAULT 3,
  p_strike_window_hours  INT     DEFAULT 168
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
           WHEN last_banned_at IS NOT NULL
                AND last_banned_at > NOW() - (GREATEST(p_strike_window_hours, 1) || ' hours')::interval
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

COMMENT ON FUNCTION release_proxy_lease(text, uuid, boolean, integer, integer, integer) IS
  'Release lease; banned=true áp cooldown pool-wide (mặc định 1 ngày) + tự tắt is_active nếu bị ban lặp lại (>= p_max_strikes trong p_strike_window_hours giờ, mặc định 7 ngày).';
