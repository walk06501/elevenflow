import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  pickAndLease,
  nextLeaseEtaSeconds,
  countSessionLeases,
  toHTTPUrl,
  toSOCKS5Url,
  releaseLease,
  markRotated,
  updateProxyEndpoint,
  deleteProxyById,
} from "../supabase";
import { rotateProxyxoay } from "../proxyxoay";
import { requireCommercialSession } from "../commercialGate";

/** POST /api/proxy/lease */
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

  const body = (req.body ?? {}) as { exclude_url?: string };
  const excludeUrl = typeof body.exclude_url === "string" ? body.exclude_url : undefined;

  const maxLeases = Math.max(
    3,
    Math.max(1, parseInt(process.env.MAX_LEASES_PER_SESSION ?? "3", 10))
  );

  let proxy;
  try {
    proxy = await pickAndLease(sessionId, excludeUrl, maxLeases);
  } catch (e) {
    return res.status(500).json({ error: String(e) });
  }
  if (!proxy) {
    let active = 0;
    try {
      active = await countSessionLeases(sessionId);
    } catch {
      active = 0;
    }
    if (active >= maxLeases) {
      return res.status(200).json({
        status: "wait",
        seconds: 5,
        reason: `session_lease_cap:${maxLeases}`,
        max_leases: maxLeases,
      });
    }
    const eta = await nextLeaseEtaSeconds();
    return res.status(200).json({
      status: "wait",
      seconds: eta,
      reason: "all proxies leased or in 60s cooldown",
    });
  }

  // 2 nguồn, ưu tiên webshare > proxyxoay (migration 015 — đã bỏ hẳn 1ip.vn):
  //  - webshare: api_key rỗng, không có API đổi IP theo request → bỏ qua
  //    hoàn toàn (nhanh nhất, không tốn round-trip).
  //  - proxyxoay: có api_key, gọi get.php để xoay + LUÔN đồng bộ lại
  //    http_host/http_port/socks_host/socks_port theo response mới nhất.
  const source = proxy.source || "";
  const skipChangeIp = source !== "proxyxoay" || !proxy.api_key || !proxy.api_key.trim();
  let cooldownSeconds = 60;

  if (source === "proxyxoay" && !skipChangeIp) {
    const result = await rotateProxyxoay(proxy.api_key);
    if (!result.ok) {
      try {
        await releaseLease(sessionId, proxy.lease_token!);
      } catch {
        // ignore
      }
      if (result.dead) {
        // Key hết hạn/không tồn tại (status 101/102) — xoá khỏi DB theo yêu cầu,
        // để pool không tiếp tục chọn phải key chết này ở các lượt sau.
        try {
          await deleteProxyById(proxy.id);
        } catch {
          // ignore
        }
      }
      return res.status(200).json({
        status: "wait",
        seconds: Math.max(1, result.waitSeconds),
        reason: "rotation_wait",
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
        // Cập nhật lỗi thì vẫn dùng endpoint cũ trong response — không chặn user.
      }
    }
  } else {
    // webshare (hoặc nguồn lạ không xác định) — không có API xoay, phục vụ ngay.
    cooldownSeconds = 0;
  }
  // markRotated giữ nguyên cho cả 2 nguồn — công bằng LRU khi xoay vòng pool
  // (dòng webshare không bị cooldown chặn lease lại nhờ migration 011).
  await markRotated(proxy.id);

  return res.status(200).json({
    status: "ok",
    lease_token: proxy.lease_token,
    proxy_http: toHTTPUrl(proxy),
    proxy_socks5: toSOCKS5Url(proxy),
    cooldown_seconds: cooldownSeconds,
  });
}
