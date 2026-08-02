import type { VercelRequest } from "@vercel/node";
import { supabase } from "./supabase";
import { ensureMonthlyQuotaAndSubscription } from "./commercialMonth";
import { userIdFromSupabaseAccessJwt } from "./verifySupabaseUserJwt";

function firstHeader(
  v: string | string[] | undefined
): string | undefined {
  if (typeof v === "string") return v;
  if (Array.isArray(v) && v.length > 0 && typeof v[0] === "string") {
    return v[0];
  }
  return undefined;
}

/** Bật khi COMMERCIAL_AUTH=true — mọi /api/proxy/* (trừ khi tách riêng) cần JWT + X-Device-ID. */
export function commercialAuthEnabled(): boolean {
  const v = (process.env.COMMERCIAL_AUTH ?? "").toLowerCase().trim();
  return v === "true" || v === "1" || v === "yes";
}

export type GateFail = { ok: false; status: number; error: string };
export type GateOk = { ok: true };
export type GateResult = GateOk | GateFail;

/** Đọc X-Device-ID (Node lower-case keys; giá trị đôi khi là string[]). */
export function deviceFingerprintFromRequest(req: VercelRequest): string | null {
  const raw = firstHeader(req.headers["x-device-id"]);
  if (!raw) return null;
  const dev = raw.trim();
  if (dev.length < 8 || dev.length > 256) {
    return null;
  }
  return dev;
}

/**
 * Gắn fingerprint với user trong licensed_devices (idempotent).
 * Luôn ghi DB khi gọi — dùng sau /api/auth/login|refresh (admin cần thấy thiết bị)
 * và từ requireCommercialSession khi COMMERCIAL_AUTH bật.
 */
export async function upsertLicensedDeviceForUser(
  userId: string,
  deviceFingerprint: string
): Promise<GateResult> {
  const dev = deviceFingerprint.trim();
  if (dev.length < 8 || dev.length > 256) {
    return { ok: false, status: 401, error: "missing_or_invalid_device_id" };
  }

  const rawMax = (process.env.MAX_DEVICES_PER_USER ?? "1").trim();
  const parsedMax = parseInt(rawMax, 10);
  const maxDev = Number.isFinite(parsedMax) ? Math.max(1, parsedMax) : 1;

  const { data: existing, error: e1 } = await supabase
    .from("licensed_devices")
    .select("id")
    .eq("user_id", userId)
    .eq("device_fingerprint", dev)
    .maybeSingle();
  if (e1) {
    console.error("licensed_devices select", e1);
    return { ok: false, status: 500, error: "device_check_failed" };
  }
  if (existing) return { ok: true };

  const { count, error: e2 } = await supabase
    .from("licensed_devices")
    .select("*", { count: "exact", head: true })
    .eq("user_id", userId);
  if (e2) {
    console.error("licensed_devices count", e2);
    return { ok: false, status: 500, error: "device_check_failed" };
  }
  if ((count ?? 0) >= maxDev) {
    return { ok: false, status: 403, error: "device_limit_reached" };
  }

  const { error: e3 } = await supabase.from("licensed_devices").insert({
    user_id: userId,
    device_fingerprint: dev,
  });
  if (e3) {
    const code = (e3 as { code?: string }).code;
    if (code === "23505") return { ok: true };
    if (code === "42P01") {
      return { ok: false, status: 500, error: "licensed_devices_table_missing_run_migration_006" };
    }
    console.error("licensed_devices insert", e3);
    return { ok: false, status: 500, error: "device_register_failed" };
  }
  return { ok: true };
}

/** Chỉ khi COMMERCIAL_AUTH — dùng cho /api/proxy/*. */
export async function ensureLicensedDevice(
  userId: string,
  deviceFingerprint: string
): Promise<GateResult> {
  if (!commercialAuthEnabled()) return { ok: true };
  return upsertLicensedDeviceForUser(userId, deviceFingerprint);
}

/**
 * Xác minh Bearer = Supabase access JWT (HS256) + đăng ký / khớp device_fingerprint.
 * Thiết bị mới: auto-insert nếu chưa vượt MAX_DEVICES_PER_USER.
 */
export async function requireCommercialSession(req: VercelRequest): Promise<GateResult> {
  if (!commercialAuthEnabled()) return { ok: true };

  const authz = req.headers.authorization;
  if (typeof authz !== "string" || !authz.startsWith("Bearer ")) {
    return { ok: false, status: 401, error: "missing_bearer" };
  }
  const raw = authz.slice(7).trim();
  if (!raw) return { ok: false, status: 401, error: "missing_bearer" };

  const userId = await userIdFromSupabaseAccessJwt(raw);
  if (!userId) {
    return { ok: false, status: 401, error: "invalid_token" };
  }

  try {
    const m = await ensureMonthlyQuotaAndSubscription(userId);
    if (!m.ok) {
      return { ok: false, status: 403, error: "subscription_expired" };
    }
  } catch {
    return { ok: false, status: 500, error: "monthly_quota_check_failed" };
  }

  const dev = deviceFingerprintFromRequest(req);
  if (!dev) {
    return { ok: false, status: 401, error: "missing_or_invalid_device_id" };
  }

  return ensureLicensedDevice(userId, dev);
}
