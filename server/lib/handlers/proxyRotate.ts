import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  pickProxy,
  markRotated,
  toHTTPUrl,
  toSOCKS5Url,
  updateProxyEndpoint,
  deleteProxyById,
} from "../supabase";
import { rotateProxyxoay } from "../proxyxoay";
import { requireCommercialSession } from "../commercialGate";

/** POST /api/proxy/rotate */
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

  const proxy = await pickProxy();
  if (!proxy) {
    return res.status(503).json({ error: "no proxy available" });
  }

  // 2 nguồn, ưu tiên webshare > proxyxoay — xem proxyLease.ts.
  const source = proxy.source || "";
  const skipChangeIp = source !== "proxyxoay" || !proxy.api_key || !proxy.api_key.trim();

  if (source === "proxyxoay" && !skipChangeIp) {
    const result = await rotateProxyxoay(proxy.api_key);
    if (!result.ok) {
      if (result.dead) {
        try {
          await deleteProxyById(proxy.id);
        } catch {
          // ignore
        }
      }
      return res.status(200).json({
        status: "wait",
        seconds: Math.max(1, result.waitSeconds),
        proxy_http: toHTTPUrl(proxy),
        proxy_socks5: toSOCKS5Url(proxy),
      });
    }
    if (result.httpHost && result.httpPort && result.socksHost && result.socksPort) {
      try {
        await updateProxyEndpoint(proxy.id, {
          httpHost: result.httpHost,
          httpPort: result.httpPort,
          socksHost: result.socksHost,
          socksPort: result.socksPort,
        });
        proxy.http_host = result.httpHost;
        proxy.http_port = result.httpPort;
        proxy.socks_host = result.socksHost;
        proxy.socks_port = result.socksPort;
      } catch {
        // ignore — vẫn dùng endpoint cũ trong response
      }
    }
  }
  // webshare (hoặc nguồn lạ không xác định) — không có API xoay, phục vụ ngay.
  await markRotated(proxy.id);

  return res.status(200).json({
    status: "ok",
    seconds: 0,
    proxy_http: toHTTPUrl(proxy),
    proxy_socks5: toSOCKS5Url(proxy),
  });
}
