import type { VercelRequest, VercelResponse } from "@vercel/node";
import { userIdFromTokenGrant } from "../authTokenGrantUserId";
import {
  commercialAuthEnabled,
  deviceFingerprintFromRequest,
  upsertLicensedDeviceForUser,
} from "../commercialGate";
import { ensureMonthlyQuotaAndSubscription } from "../commercialMonth";

/** POST /api/auth/refresh */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "method not allowed" });
  }
  const secret = req.headers["x-app-secret"];
  if (!process.env.APP_SECRET || secret !== process.env.APP_SECRET) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const anon = process.env.SUPABASE_ANON_KEY;
  if (!supabaseUrl || !anon) {
    return res.status(500).json({ error: "server_misconfigured" });
  }

  const body = (req.body ?? {}) as { refresh_token?: string };
  const refreshToken = typeof body.refresh_token === "string" ? body.refresh_token : "";
  if (!refreshToken) {
    return res.status(400).json({ error: "missing_refresh_token" });
  }

  const base = supabaseUrl.replace(/\/+$/, "");
  const tokenUrl = `${base}/auth/v1/token?grant_type=refresh_token`;
  const resp = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: anon,
      Authorization: `Bearer ${anon}`,
    },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  const data = (await resp.json().catch(() => ({}))) as Record<string, unknown>;
  if (!resp.ok) {
    return res.status(401).json({ error: "refresh_failed" });
  }

  const user = data.user as { id?: string; email?: string } | undefined;
  const userId = userIdFromTokenGrant(data);
  if (commercialAuthEnabled() && userId) {
    try {
      const m = await ensureMonthlyQuotaAndSubscription(userId);
      if (!m.ok) {
        return res.status(403).json({
          error: "subscription_expired",
          message:
            "Gói đã hết hạn (theo ngày admin đặt). Liên hệ để gia hạn.",
        });
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes("migration")) {
        return res.status(500).json({ error: msg });
      }
      return res.status(500).json({ error: "subscription_check_failed" });
    }
  }
  const dev = deviceFingerprintFromRequest(req);
  if (userId && dev) {
    const gate = await upsertLicensedDeviceForUser(userId, dev);
    if (!gate.ok) {
      return res.status(gate.status).json({ error: gate.error });
    }
  }

  return res.status(200).json({
    access_token: data.access_token as string,
    refresh_token: (data.refresh_token as string) || refreshToken,
    expires_in: typeof data.expires_in === "number" ? data.expires_in : 3600,
    user: { id: user?.id, email: user?.email },
  });
}
