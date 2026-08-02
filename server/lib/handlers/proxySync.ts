import type { VercelRequest, VercelResponse } from "@vercel/node";
import { syncWebshareProxies } from "../webshare";

/**
 * POST /api/cron/sync-proxies — gọi API Webshare lấy list mới nhất, upsert
 * vào pool (source='webshare'), tắt IP đã bị nhà cung cấp thay. Bảo vệ bằng
 * CRON_SECRET riêng (fallback APP_SECRET) — Vercel Cron gọi định kỳ
 * (vercel.json), hoặc gọi tay khi cần refresh ngay (khách đang gấp).
 */
export default async function proxySync(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST" && req.method !== "GET") {
    return res.status(405).json({ error: "method not allowed" });
  }

  const expected = process.env.CRON_SECRET || process.env.APP_SECRET;
  if (!expected) {
    return res.status(500).json({ error: "missing_cron_secret_config" });
  }
  const provided =
    req.headers["x-cron-secret"] ??
    req.headers["x-app-secret"] ??
    (req.headers.authorization?.toString().replace(/^Bearer\s+/i, "") ?? "");
  if (provided !== expected) {
    return res.status(401).json({ error: "unauthorized" });
  }

  try {
    const result = await syncWebshareProxies();
    return res.status(result.ok ? 200 : 502).json(result);
  } catch (e) {
    return res.status(500).json({ error: String((e as Error)?.message ?? e) });
  }
}
