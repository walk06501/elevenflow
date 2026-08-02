import type { VercelRequest, VercelResponse } from "@vercel/node";
import health from "../lib/handlers/health";
import config from "../lib/handlers/config";
import authLogin from "../lib/handlers/authLogin";
import authRefresh from "../lib/handlers/authRefresh";
import proxyLease from "../lib/handlers/proxyLease";
import proxyHeartbeat from "../lib/handlers/proxyHeartbeat";
import proxyRelease from "../lib/handlers/proxyRelease";
import proxyRotate from "../lib/handlers/proxyRotate";
import proxyCurrent from "../lib/handlers/proxyCurrent";
import proxyCapacity from "../lib/handlers/proxyCapacity";
import adminLogin from "../lib/handlers/adminLogin";
import adminUsers from "../lib/handlers/adminUsers";
import adminDevices from "../lib/handlers/adminDevices";
import adminUserDelete from "../lib/handlers/adminUserDelete";
import adminUserQuota from "../lib/handlers/adminUserQuota";
import adminProxies from "../lib/handlers/adminProxies";
import proxySync from "../lib/handlers/proxySync";
import commercialQuotaCheck from "../lib/handlers/commercialQuotaCheck";
import commercialQuotaConsume from "../lib/handlers/commercialQuotaConsume";

type RouteFn = (
  req: VercelRequest,
  res: VercelResponse
) => void | VercelResponse | Promise<void | VercelResponse>;

function decodeSeg(s: string): string[] {
  try {
    return decodeURIComponent(s).split("/").filter(Boolean);
  } catch {
    return s.split("/").filter(Boolean);
  }
}

/** Production: vercel.json rewrite → /api/dispatch?__segments=<path>. Dev: path /api/... trực tiếp. */
function getSegments(req: VercelRequest): string[] {
  const q = req.query.__segments;
  if (typeof q === "string" && q.trim()) {
    return decodeSeg(q);
  }
  if (Array.isArray(q) && q.length && typeof q[0] === "string" && q[0].trim()) {
    return decodeSeg(q.join("/"));
  }

  let pathname = (req.url || "").split("?")[0] || "";
  if (pathname.includes("://")) {
    try {
      pathname = new URL(pathname).pathname;
    } catch {
      /* */
    }
  }
  let cleaned = pathname.replace(/^\/api\/?/i, "").replace(/\/+$/, "");
  if (/^dispatch\/?$/i.test(cleaned)) {
    cleaned = "";
  }
  return cleaned ? cleaned.split("/").filter(Boolean) : [];
}

/** Một Serverless Function cho toàn bộ /api/* — Hobby: 1 function + rewrite đa cấp. */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  const method = (req.method || "GET").toUpperCase();
  const segments = getSegments(req);
  const path = segments.join("/");

  const table: Record<string, RouteFn> = {
    "GET/health": health,
    "GET/config": config,
    "POST/auth/login": authLogin,
    "POST/auth/refresh": authRefresh,
    "POST/proxy/lease": proxyLease,
    "POST/proxy/heartbeat": proxyHeartbeat,
    "POST/proxy/release": proxyRelease,
    "POST/proxy/rotate": proxyRotate,
    "GET/proxy/current": proxyCurrent,
    "GET/proxy/capacity": proxyCapacity,
    "POST/admin/login": adminLogin,
    "GET/admin/users": adminUsers,
    "POST/admin/users": adminUsers,
    "GET/admin/devices": adminDevices,
    "POST/admin/devices": adminDevices,
    "POST/admin/user-delete": adminUserDelete,
    "POST/admin/user-quota": adminUserQuota,
    "GET/admin/proxies": adminProxies,
    "POST/admin/proxies": adminProxies,
    "GET/cron/sync-proxies": proxySync,
    "POST/cron/sync-proxies": proxySync,
    "POST/commercial/quota-check": commercialQuotaCheck,
    "POST/commercial/quota-consume": commercialQuotaConsume,
  };

  const key = `${method}/${path}`;
  const fn = table[key];
  if (!fn) {
    return res.status(404).json({ error: "not_found", path: `/api/${path || ""}` });
  }
  return fn(req, res);
}
