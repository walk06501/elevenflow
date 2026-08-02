import type { VercelRequest, VercelResponse } from "@vercel/node";
import { supabase } from "../supabase";
import { commercialAuthEnabled, deviceFingerprintFromRequest } from "../commercialGate";
import { ensureMonthlyQuotaAndSubscription } from "../commercialMonth";
import { userIdFromSupabaseAccessJwt } from "../verifySupabaseUserJwt";

/** POST /api/commercial/quota-consume — Bearer + X-Device-ID + X-App-Secret; body { chars: number } */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "method not allowed" });
  }
  if (!commercialAuthEnabled()) {
    return res.status(200).json({ ok: true, skipped: true });
  }

  const appSec = req.headers["x-app-secret"];
  if (!process.env.APP_SECRET || appSec !== process.env.APP_SECRET) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const authz = req.headers.authorization;
  if (typeof authz !== "string" || !authz.startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing_bearer" });
  }
  const raw = authz.slice(7).trim();
  const userId = await userIdFromSupabaseAccessJwt(raw);
  if (!userId) {
    return res.status(401).json({ error: "invalid_token" });
  }

  if (!deviceFingerprintFromRequest(req)) {
    return res.status(401).json({ error: "missing_or_invalid_device_id" });
  }

  try {
    const m = await ensureMonthlyQuotaAndSubscription(userId);
    if (!m.ok) {
      return res.status(403).json({
        ok: false,
        error: "subscription_expired",
        message: "Gói đã hết hạn. Liên hệ admin để gia hạn.",
      });
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("migration")) {
      return res.status(500).json({ error: msg });
    }
    return res.status(500).json({ error: msg });
  }

  const body = (req.body ?? {}) as { chars?: number };
  const chars = typeof body.chars === "number" && body.chars >= 0 ? Math.floor(body.chars) : -1;
  if (chars < 0) {
    return res.status(400).json({ error: "missing_chars" });
  }
  if (chars === 0) {
    return res.status(200).json({ ok: true, chars_used: 0, max_chars: 0, reason: "zero" });
  }

  const { data, error } = await supabase.rpc("commercial_consume_chars", {
    p_user_id: userId,
    p_chars: chars,
  });

  if (error) {
    if (error.message?.includes("function") || (error as { code?: string }).code === "42883") {
      return res.status(500).json({ error: "commercial_consume_chars_missing_run_migration_007" });
    }
    return res.status(500).json({ error: error.message });
  }

  const j = data as Record<string, unknown> | null;
  if (!j || j.ok !== true) {
    return res.status(403).json({
      ok: false,
      error: typeof j?.reason === "string" ? j.reason : "quota_exceeded",
      chars_used: j?.chars_used,
      max_chars: j?.max_chars,
      remaining: j?.remaining,
    });
  }

  return res.status(200).json({
    ok: true,
    chars_used: j.chars_used,
    max_chars: j.max_chars,
    remaining: j.remaining,
    reason: j.reason,
  });
}
