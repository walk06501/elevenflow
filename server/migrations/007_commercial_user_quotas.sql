-- Hạn mức ký tự TTS theo user (admin set max_chars; desktop báo tiêu thụ sau batch).
-- max_chars = 0 → không giới hạn (mặc định khi chưa có dòng).

CREATE TABLE IF NOT EXISTS public.commercial_user_quotas (
  user_id    UUID PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  max_chars  BIGINT NOT NULL DEFAULT 0,
  chars_used BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT commercial_user_quotas_nonneg CHECK (max_chars >= 0 AND chars_used >= 0)
);

CREATE INDEX IF NOT EXISTS idx_commercial_user_quotas_updated
  ON public.commercial_user_quotas (updated_at DESC);

ALTER TABLE public.commercial_user_quotas ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE public.commercial_user_quotas IS
  'max_chars=0 không hạn; chars_used tăng khi desktop POST /api/commercial/quota-consume (JWT).';

-- Cộng dồn atomically; trả JSON cho serverless.
CREATE OR REPLACE FUNCTION public.commercial_consume_chars(p_user_id UUID, p_chars BIGINT)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  r public.commercial_user_quotas%ROWTYPE;
  new_used BIGINT;
BEGIN
  IF p_chars IS NULL OR p_chars < 0 THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'invalid_chars');
  END IF;

  SELECT * INTO r FROM public.commercial_user_quotas WHERE user_id = p_user_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object(
      'ok', true,
      'chars_used', 0,
      'max_chars', 0,
      'remaining', NULL::bigint,
      'reason', 'no_quota_unlimited'
    );
  END IF;

  IF r.max_chars = 0 THEN
    RETURN jsonb_build_object(
      'ok', true,
      'chars_used', r.chars_used,
      'max_chars', 0,
      'remaining', NULL::bigint,
      'reason', 'unlimited'
    );
  END IF;

  IF r.chars_used + p_chars > r.max_chars THEN
    RETURN jsonb_build_object(
      'ok', false,
      'chars_used', r.chars_used,
      'max_chars', r.max_chars,
      'remaining', GREATEST(0::BIGINT, r.max_chars - r.chars_used),
      'reason', 'quota_exceeded'
    );
  END IF;

  new_used := r.chars_used + p_chars;
  UPDATE public.commercial_user_quotas
  SET chars_used = new_used, updated_at = NOW()
  WHERE user_id = p_user_id;

  RETURN jsonb_build_object(
    'ok', true,
    'chars_used', new_used,
    'max_chars', r.max_chars,
    'remaining', r.max_chars - new_used,
    'reason', 'consumed'
  );
END;
$$;

REVOKE ALL ON FUNCTION public.commercial_consume_chars(UUID, BIGINT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.commercial_consume_chars(UUID, BIGINT) TO service_role;
