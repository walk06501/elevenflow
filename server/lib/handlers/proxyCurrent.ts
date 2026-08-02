import type { VercelRequest, VercelResponse } from "@vercel/node";
import { pickProxy, toHTTPUrl, toSOCKS5Url } from "../supabase";
import { requireCommercialSession } from "../commercialGate";

/** GET /api/proxy/current */
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

  const proxy = await pickProxy();
  if (!proxy) {
    return res.status(503).json({ error: "no proxy available" });
  }

  return res.status(200).json({
    proxy_http: toHTTPUrl(proxy),
    proxy_socks5: toSOCKS5Url(proxy),
  });
}
