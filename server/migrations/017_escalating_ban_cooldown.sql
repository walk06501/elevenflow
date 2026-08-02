-- Migration 017: SỬA LỖI NGHIÊM TRỌNG — cooldown ban cố định 1 ngày (migration
-- 016) áp dụng cho MỌI lần bị ban kể cả lần đầu, khiến gần hết pool active
-- (297/297) bị khoá cùng lúc chỉ trong ~14 tiếng, dẫn tới "không có proxy nào
-- rảnh" (đã xử lý khẩn cấp bằng cách gỡ banned_until cho các dòng ban_count<3).
--
-- Nguyên nhân: pool chỉ ~300-600 IP nhưng bị ban rất thường xuyên. Cooldown
-- 1 ngày FLAT cho lần ban ĐẦU TIÊN quá nặng tay — tỷ lệ ban/pool cao hơn tỷ lệ
-- hồi phục, dẫn tới cả pool "chết" đồng thời.
--
-- Giải pháp: cooldown LUỸ TIẾN theo ban_count (nhẹ tay lần đầu, nặng dần nếu
-- tái phạm) — KHÔNG tự loại khỏi pool (is_active=false) nữa, vì pool có hạn:
-- loại vĩnh viễn dần dần sẽ khiến hết proxy để dùng. Thay vào đó cứ hết
-- cooldown là proxy quay lại phục vụ bình thường, lặp lại vô hạn:
--   Bị ban lần 1  → cooldown ngắn (mặc định 15 phút,  PROXY_BAN_COOLDOWN_TIER1_MINUTES)
--   Bị ban lần 2  → cooldown vừa  (mặc định 3 giờ,    PROXY_BAN_COOLDOWN_TIER2_MINUTES)
--   Bị ban lần 3+ → cooldown dài  (mặc định 1 ngày,   PROXY_BAN_COOLDOWN_MINUTES) —
--                    vẫn ở lại pool, hết 1 ngày lại được lease lại bình thường.
--
-- Riêng nguồn proxyxoay: KHÔNG áp cooldown/ban_count — mỗi lần dòng này được
-- lease lại, server đã tự gọi API xoay để lấy IP THẬT mới (proxyLease.ts gọi
-- rotateProxyxoay mỗi lần), nên bản chất IP luôn đổi mới ở lượt dùng kế tiếp.
-- Áp cooldown lên gateway proxyxoay chỉ làm giảm oan số key khả dụng, không
-- có tác dụng phòng ban thật sự như với Webshare (IP tĩnh, đúng là IP đó bị
-- ghi nhớ nên mới cần né ra).
--
-- Chạy trong Supabase SQL editor SAU 016_ban_cooldown_1day.sql.

DROP FUNCTION IF EXISTS release_proxy_lease(text, uuid, boolean, integer, integer, integer);

CREATE OR REPLACE FUNCTION release_proxy_lease(
  p_session_id           TEXT,
  p_lease_token           UUID,
  p_banned                BOOLEAN DEFAULT false,
  p_cooldown_minutes      INT     DEFAULT 1440,
  p_max_strikes           INT     DEFAULT 3,
  p_strike_window_hours   INT     DEFAULT 168,
  p_cooldown_tier1_minutes INT    DEFAULT 15,
  p_cooldown_tier2_minutes INT    DEFAULT 180
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
  v_id INT;
  v_source TEXT;
  v_new_ban_count INT;
BEGIN
  IF NOT p_banned THEN
    UPDATE proxies
       SET leased_by = NULL, leased_at = NULL, lease_token = NULL
     WHERE lease_token = p_lease_token
       AND leased_by = p_session_id;
    RETURN;
  END IF;

  -- Tính trước ban_count MỚI (dựa trên giá trị CŨ) rồi mới UPDATE — tránh phải
  -- lặp lại cùng 1 biểu thức CASE nhiều lần trong câu UPDATE.
  SELECT id, source,
         CASE
           WHEN last_banned_at IS NOT NULL
                AND last_banned_at > NOW() - (GREATEST(p_strike_window_hours, 1) || ' hours')::interval
             THEN COALESCE(ban_count, 0) + 1
           ELSE 1
         END
    INTO v_id, v_source, v_new_ban_count
    FROM proxies
   WHERE lease_token = p_lease_token
     AND leased_by = p_session_id
   FOR UPDATE;

  IF v_id IS NULL THEN
    RETURN;
  END IF;

  -- proxyxoay: IP thật tự đổi ngay ở lượt lease KẾ TIẾP (server gọi lại API
  -- xoay mỗi lần) — không áp cooldown/ban_count, chỉ release bình thường.
  IF v_source = 'proxyxoay' THEN
    UPDATE proxies
       SET leased_by = NULL, leased_at = NULL, lease_token = NULL
     WHERE id = v_id;
    RETURN;
  END IF;

  UPDATE proxies
     SET leased_by      = NULL,
         leased_at      = NULL,
         lease_token    = NULL,
         ban_count      = v_new_ban_count,
         last_banned_at = NOW(),
         banned_until   = NOW() + (
           CASE
             WHEN v_new_ban_count <= 1 THEN GREATEST(p_cooldown_tier1_minutes, 1)
             WHEN v_new_ban_count = 2 THEN GREATEST(p_cooldown_tier2_minutes, 1)
             ELSE GREATEST(p_cooldown_minutes, 1)
           END || ' minutes')::interval
   WHERE id = v_id;

  -- Cố tình KHÔNG tự is_active=false dù ban_count vượt p_max_strikes — pool
  -- có hạn, loại vĩnh viễn dần dần sẽ hết proxy để dùng. p_max_strikes vẫn
  -- giữ trong signature để tương thích ngược (không dùng tới nữa).
END;
$$;

COMMENT ON FUNCTION release_proxy_lease(text, uuid, boolean, integer, integer, integer, integer, integer) IS
  'Release lease; banned=true áp cooldown LUỸ TIẾN theo ban_count cho nguồn webshare (lần 1 ngắn, lần 2 vừa, lần 3+ dài 1 ngày, không bao giờ tự loại khỏi pool); nguồn proxyxoay bỏ qua cooldown hoàn toàn.';
