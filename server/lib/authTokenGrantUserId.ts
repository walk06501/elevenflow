import { decodeJwt } from "jose";

/** Lấy user UUID từ body Supabase token grant (user.id hoặc decode access_token). */
export function userIdFromTokenGrant(data: Record<string, unknown>): string {
  const user = data.user as { id?: string } | undefined;
  if (typeof user?.id === "string" && user.id.trim() !== "") {
    return user.id.trim();
  }
  const at = data.access_token;
  if (typeof at === "string" && at.length > 20) {
    try {
      const p = decodeJwt(at);
      if (typeof p.sub === "string" && p.sub) return p.sub;
    } catch {
      /* ignore */
    }
  }
  return "";
}
