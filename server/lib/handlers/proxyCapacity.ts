import type { VercelRequest, VercelResponse } from "@vercel/node";
import { countLeaseablePoolProxies } from "../supabase";
import { requireCommercialSession } from "../commercialGate";

function effectiveMaxLeasesPerSession(): number {
  const raw = process.env.MAX_LEASES_PER_SESSION ?? "3";
  const parsed = Math.max(1, parseInt(raw, 10));
  return Math.max(3, parsed);
}

/** GET /api/proxy/capacity — pool_count + max_leases (autoscale worker client). */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "GET") {
    return res.status(405).json({ error: "method not allowed" });
  }
  const secret = req.headers["x-app-secret"];
  if (!process.env.APP_SECRET || secret !== process.env.APP_SECRET) {
    return res.status(401).json({ error: "unauthorized" });
  }
  const gate = await requireCommercialSession(req);
  if (!gate.ok) {
    return res.status(gate.status).json({ error: gate.error });
  }

  let poolCount = 0;
  try {
    poolCount = await countLeaseablePoolProxies();
  } catch (e) {
    return res.status(500).json({ error: String(e) });
  }

  return res.status(200).json({
    pool_count: poolCount,
    max_leases: effectiveMaxLeasesPerSession(),
  });
}
