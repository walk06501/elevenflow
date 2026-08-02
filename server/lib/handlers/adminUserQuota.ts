import type { VercelRequest, VercelResponse } from "@vercel/node";
import { supabase } from "../supabase";
import { requireAdminJWT } from "../adminAuth";
import { addCalendarMonthsUtc, currentQuotaMonthKey } from "../commercialMonth";

/** POST /api/admin/user-quota — body { action, user_id, max_chars?, expires_at?, months? } */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (!(await requireAdminJWT(req, res))) return;
  if (req.method !== "POST") {
    return res.status(405).json({ error: "method not allowed" });
  }

  const body = (req.body ?? {}) as {
    action?: string;
    user_id?: string;
    max_chars?: number;
    expires_at?: string | null;
    months?: number;
  };
  const action = typeof body.action === "string" ? body.action.trim() : "";
  const userId = typeof body.user_id === "string" ? body.user_id.trim() : "";

  if (!userId) {
    return res.status(400).json({ error: "missing_user_id" });
  }

  if (action === "reset_usage") {
    const { error } = await supabase
      .from("commercial_user_quotas")
      .update({ chars_used: 0, updated_at: new Date().toISOString() })
      .eq("user_id", userId);
    if (error) {
      if ((error as { code?: string }).code === "42P01") {
        return res.status(500).json({ error: "commercial_user_quotas_missing_run_migration_007" });
      }
      return res.status(500).json({ error: error.message });
    }
    return res.status(200).json({ ok: true });
  }

  if (action === "set_subscription_expires") {
    const raw = body.expires_at;
    let expiresIso: string | null;
    if (raw === null || raw === undefined || raw === "") {
      expiresIso = null;
    } else if (typeof raw === "string") {
      const t = Date.parse(raw);
      if (Number.isNaN(t)) {
        return res.status(400).json({ error: "invalid_expires_at" });
      }
      expiresIso = new Date(t).toISOString();
    } else {
      return res.status(400).json({ error: "invalid_expires_at" });
    }

    const { data: ex, error: selErr } = await supabase
      .from("commercial_user_quotas")
      .select("user_id")
      .eq("user_id", userId)
      .maybeSingle();

    if (selErr) {
      if ((selErr as { code?: string }).code === "42P01") {
        return res.status(500).json({ error: "commercial_user_quotas_missing_run_migration_007" });
      }
      if ((selErr as { code?: string }).code === "42703") {
        return res.status(500).json({ error: "commercial_user_quotas_missing_run_migration_008" });
      }
      return res.status(500).json({ error: selErr.message });
    }

    const now = new Date().toISOString();
    const month = currentQuotaMonthKey();
    if (ex) {
      const { error } = await supabase
        .from("commercial_user_quotas")
        .update({
          subscription_expires_at: expiresIso,
          updated_at: now,
        })
        .eq("user_id", userId);
      if (error) {
        if ((error as { code?: string }).code === "42703") {
          return res.status(500).json({ error: "commercial_user_quotas_missing_run_migration_008" });
        }
        return res.status(500).json({ error: error.message });
      }
    } else {
      const { error } = await supabase.from("commercial_user_quotas").insert({
        user_id: userId,
        max_chars: 0,
        chars_used: 0,
        quota_month: month,
        subscription_expires_at: expiresIso,
        updated_at: now,
      });
      if (error) {
        if ((error as { code?: string }).code === "42703") {
          return res.status(500).json({ error: "commercial_user_quotas_missing_run_migration_008" });
        }
        return res.status(500).json({ error: error.message });
      }
    }
    return res.status(200).json({ ok: true, user_id: userId, subscription_expires_at: expiresIso });
  }

  if (action === "extend_subscription") {
    const mr = body.months;
    let months =
      typeof mr === "number" && Number.isFinite(mr) && mr > 0 ? Math.floor(mr) : 1;
    months = Math.min(120, Math.max(1, months));

    const { data: row, error: selErr } = await supabase
      .from("commercial_user_quotas")
      .select("user_id, subscription_expires_at")
      .eq("user_id", userId)
      .maybeSingle();

    if (selErr) {
      if ((selErr as { code?: string }).code === "42P01") {
        return res.status(500).json({ error: "commercial_user_quotas_missing_run_migration_007" });
      }
      if ((selErr as { code?: string }).code === "42703") {
        return res.status(500).json({ error: "commercial_user_quotas_missing_run_migration_008" });
      }
      return res.status(500).json({ error: selErr.message });
    }
    if (!row) {
      return res.status(400).json({
        error: "no_quota_row",
        message: "Chưa có dòng quota — bấm «Lưu hạn» (max ký tự) trước, rồi gia hạn.",
      });
    }

    const nowMs = Date.now();
    let base = new Date(nowMs);
    const cur = row.subscription_expires_at
      ? new Date(String(row.subscription_expires_at))
      : null;
    if (cur && !Number.isNaN(cur.getTime()) && cur.getTime() > nowMs) {
      base = cur;
    }

    const newExp = addCalendarMonthsUtc(base, months);
    const month = currentQuotaMonthKey();
    const ts = new Date().toISOString();
    const { error: upErr } = await supabase
      .from("commercial_user_quotas")
      .update({
        subscription_expires_at: newExp.toISOString(),
        chars_used: 0,
        quota_month: month,
        updated_at: ts,
      })
      .eq("user_id", userId);
    if (upErr) {
      if ((upErr as { code?: string }).code === "42703") {
        return res.status(500).json({ error: "commercial_user_quotas_missing_run_migration_008" });
      }
      return res.status(500).json({ error: upErr.message });
    }
    return res.status(200).json({
      ok: true,
      user_id: userId,
      subscription_expires_at: newExp.toISOString(),
      months_added: months,
    });
  }

  if (action !== "set_max") {
    return res.status(400).json({ error: "unknown_action" });
  }

  const maxRaw = body.max_chars;
  const maxChars =
    typeof maxRaw === "number" && Number.isFinite(maxRaw) && maxRaw >= 0
      ? Math.floor(maxRaw)
      : -1;
  if (maxChars < 0) {
    return res.status(400).json({ error: "missing_or_invalid_max_chars" });
  }

  const { data: ex, error: selErr } = await supabase
    .from("commercial_user_quotas")
    .select("user_id")
    .eq("user_id", userId)
    .maybeSingle();

  if (selErr) {
    if ((selErr as { code?: string }).code === "42P01") {
      return res.status(500).json({ error: "commercial_user_quotas_missing_run_migration_007" });
    }
    if ((selErr as { code?: string }).code === "42703") {
      return res.status(500).json({ error: "commercial_user_quotas_missing_run_migration_008" });
    }
    return res.status(500).json({ error: selErr.message });
  }

  const now = new Date().toISOString();
  const month = currentQuotaMonthKey();
  if (ex) {
    const { error } = await supabase
      .from("commercial_user_quotas")
      .update({ max_chars: maxChars, updated_at: now })
      .eq("user_id", userId);
    if (error) return res.status(500).json({ error: error.message });
  } else {
    const firstExp =
      maxChars > 0 ? addCalendarMonthsUtc(new Date(), 1) : null;
    const { error } = await supabase.from("commercial_user_quotas").insert({
      user_id: userId,
      max_chars: maxChars,
      chars_used: 0,
      quota_month: month,
      subscription_expires_at: firstExp ? firstExp.toISOString() : null,
      updated_at: now,
    });
    if (error) return res.status(500).json({ error: error.message });
  }

  return res.status(200).json({ ok: true, user_id: userId, max_chars: maxChars });
}
