import type { VercelRequest, VercelResponse } from "@vercel/node";
import { releaseLease } from "../supabase";
import { requireCommercialSession } from "../commercialGate";

/** POST /api/proxy/release */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") {
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
  const sessionId = req.headers["x-session-id"];
  if (!sessionId || typeof sessionId !== "string") {
    return res.status(400).json({ error: "missing X-Session-ID header" });
  }

  const body = (req.body ?? {}) as { lease_token?: string; banned?: boolean };
  if (!body.lease_token) {
    return res.status(400).json({ error: "missing lease_token" });
  }

  try {
    await releaseLease(sessionId, body.lease_token, Boolean(body.banned));
  } catch (e) {
    return res.status(500).json({ error: String(e) });
  }
  return res.status(200).json({ status: "ok" });
}
