import { supabase } from "./supabase";

/** Múi giờ tính “tháng” cho reset quota (mặc định VN). */
export function commercialQuotaTimeZone(): string {
  const z = (process.env.COMMERCIAL_QUOTA_TZ ?? "Asia/Ho_Chi_Minh").trim();
  return z || "UTC";
}

/** Khóa YYYY-MM theo múi giờ quota. */
export function currentQuotaMonthKey(d = new Date()): string {
  const tz = commercialQuotaTimeZone();
  try {
    const parts = new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      year: "numeric",
      month: "2-digit",
    }).formatToParts(d);
    const y = parts.find((p) => p.type === "year")?.value;
    const m = parts.find((p) => p.type === "month")?.value;
    if (y && m) return `${y}-${m}`;
  } catch {
    /* fallthrough UTC */
  }
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

/** Cộng m tháng dương lịch (UTC) — dùng cho ngày hết hạn gói / gia hạn. */
export function addCalendarMonthsUtc(from: Date, months: number): Date {
  const m = Number.isFinite(months) ? Math.floor(months) : 0;
  const caps = Math.min(120, Math.max(1, m));
  const d = new Date(from.getTime());
  const day = d.getUTCDate();
  d.setUTCMonth(d.getUTCMonth() + caps);
  if (d.getUTCDate() !== day) {
    d.setUTCDate(0);
  }
  return d;
}

export type MonthlyQuotaGate =
  | { ok: true; hasQuotaRow: boolean }
  | { ok: false; reason: "subscription_expired" };

/**
 * Nếu có dòng quota: (1) quá subscription_expires_at → khóa; (2) không có ngày hết hạn gói
 * và có max_chars > 0: sang tháng dương lịch (quota_month) → reset chars_used.
 * Có ngày hết hạn gói → một kỳ theo gói (không reset theo tháng dương lịch); gia hạn / xóa đếm do admin.
 */
export async function ensureMonthlyQuotaAndSubscription(
  userId: string
): Promise<MonthlyQuotaGate> {
  const { data: row, error } = await supabase
    .from("commercial_user_quotas")
    .select(
      "quota_month, chars_used, subscription_expires_at, max_chars"
    )
    .eq("user_id", userId)
    .maybeSingle();

  if (error) {
    if ((error as { code?: string }).code === "42P01") {
      throw new Error("commercial_user_quotas_missing_run_migration_007");
    }
    if ((error as { code?: string }).code === "42703") {
      throw new Error("commercial_user_quotas_missing_run_migration_008");
    }
    throw new Error(error.message);
  }

  if (!row) {
    return { ok: true, hasQuotaRow: false };
  }

  const ex = row.subscription_expires_at as string | null | undefined;
  if (ex) {
    const t = new Date(ex).getTime();
    if (!Number.isNaN(t) && Date.now() > t) {
      return { ok: false, reason: "subscription_expired" };
    }
  }

  const maxChars = Number((row as { max_chars?: unknown }).max_chars ?? 0);
  const hasSubEnd =
    ex != null &&
    String(ex).trim() !== "" &&
    !Number.isNaN(new Date(String(ex)).getTime());

  const monthKey = currentQuotaMonthKey();
  const qm = typeof row.quota_month === "string" ? row.quota_month.trim() : "";
  // Có ngày hết hạn gói → một “kỳ” theo gói, không reset đếm theo tháng dương lịch.
  if (maxChars > 0 && !hasSubEnd && qm !== monthKey) {
    const { error: upErr } = await supabase
      .from("commercial_user_quotas")
      .update({
        chars_used: 0,
        quota_month: monthKey,
        updated_at: new Date().toISOString(),
      })
      .eq("user_id", userId);
    if (upErr) {
      if ((upErr as { code?: string }).code === "42703") {
        throw new Error("commercial_user_quotas_missing_run_migration_008");
      }
      throw new Error(upErr.message);
    }
  }

  return { ok: true, hasQuotaRow: true };
}
