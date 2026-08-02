import type { VercelRequest, VercelResponse } from "@vercel/node";
import * as jose from "jose";

/** Ký JWT phiên admin — tối thiểu 32 ký tự (Vercel env). */
export function adminSigningKey(): Uint8Array | null {
  const s = process.env.ELEVENFLOW_ADMIN_SECRET;
  if (!s || s.length < 32) return null;
  return new TextEncoder().encode(s);
}

/**
 * Các route /api/admin/* (trừ /api/admin/login) bắt buộc:
 *   Authorization: Bearer <JWT từ POST /api/admin/login>
 */
export async function requireAdminJWT(
  req: VercelRequest,
  res: VercelResponse
): Promise<boolean> {
  const key = adminSigningKey();
  if (!key) {
    res.status(503).json({
      error: "admin_not_configured",
      hint: "Set ELEVENFLOW_ADMIN_SECRET on Vercel (>= 32 chars) for signing admin sessions.",
    });
    return false;
  }
  const authz = req.headers.authorization;
  if (typeof authz !== "string" || !authz.startsWith("Bearer ")) {
    res.status(401).json({ error: "missing_admin_session" });
    return false;
  }
  const raw = authz.slice(7).trim();
  if (!raw) {
    res.status(401).json({ error: "missing_admin_session" });
    return false;
  }
  try {
    const { payload } = await jose.jwtVerify(raw, key, { algorithms: ["HS256"] });
    if (payload.role !== "admin") {
      res.status(403).json({ error: "forbidden" });
      return false;
    }
    return true;
  } catch {
    res.status(401).json({ error: "invalid_or_expired_admin_session" });
    return false;
  }
}
