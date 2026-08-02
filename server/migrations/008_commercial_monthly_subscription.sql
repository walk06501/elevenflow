-- Chu kỳ tháng + hết hạn gói (khóa commercial sau subscription_expires_at).
-- quota_month = YYYY-MM (theo COMMERCIAL_QUOTA_TZ trên server); khác tháng hiện tại → chars_used reset về 0.

ALTER TABLE public.commercial_user_quotas
  ADD COLUMN IF NOT EXISTS quota_month TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS subscription_expires_at TIMESTAMPTZ NULL;

COMMENT ON COLUMN public.commercial_user_quotas.quota_month IS
  'Tháng dương lịch (YYYY-MM) mà chars_used đang áp dụng; đổi tháng → reset chars_used.';
COMMENT ON COLUMN public.commercial_user_quotas.subscription_expires_at IS
  'Sau mốc này (UTC lưu DB): từ chối đăng nhập commercial + proxy + quota. NULL = không khóa theo ngày.';
