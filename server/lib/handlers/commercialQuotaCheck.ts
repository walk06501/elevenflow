import type { VercelRequest, VercelResponse } from "@vercel/node";
import { supabase } from "../supabase";
import { commercialAuthEnabled, deviceFingerprintFromRequest } from "../commercialGate";
import { ensureMonthlyQuotaAndSubscription } from "../commercialMonth";
import { userIdFromSupabaseAccessJwt } from "../verifySupabaseUserJwt";

/** POST /api/commercial/quota-check — Bearer + X-Device-ID + X-App-Secret; body { need_chars: number } */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "method not allowed" });
  }
  if (!commercialAuthEnabled()) {
    return res.status(200).json({ ok: true, unlimited: true });
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

  const body = (req.body ?? {}) as { need_chars?: number };
  const need = typeof body.need_chars === "number" && body.need_chars >= 0 ? Math.floor(body.need_chars) : -1;
  if (need < 0) {
    return res.status(400).json({ error: "missing_need_chars" });
  }

  const { data: row, error } = await supabase
    .from("commercial_user_quotas")
    .select("chars_used, max_chars")
    .eq("user_id", userId)
    .maybeSingle();

  if (error) {
    if ((error as { code?: string }).code === "42P01") {
      return res.status(500).json({ error: "commercial_user_quotas_missing_run_migration_007" });
    }
    return res.status(500).json({ error: error.message });
  }

  if (!row || row.max_chars === 0) {
    const usedU = Number(row?.chars_used ?? 0);
    return res.status(200).json({
      ok: true,
      unlimited: true,
      chars_used: usedU,
      max_chars: 0,
      remaining: 0,
    });
  }

  const used = Number(row.chars_used ?? 0);
  const max = Number(row.max_chars ?? 0);
  const remaining = Math.max(0, max - used);
  if (used + need > max) {
    return res.status(403).json({
      ok: false,
      error: "quota_exceeded",
      chars_used: used,
      max_chars: max,
      remaining,
      need_chars: need,
    });
  }

  return res.status(200).json({
    ok: true,
    unlimited: false,
    chars_used: used,
    max_chars: max,
    remaining: remaining - need,
    need_chars: need,
  });
}
