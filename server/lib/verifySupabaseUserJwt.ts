import * as jose from "jose";
import { supabase } from "./supabase";

/**
 * Lấy user_id từ Supabase access JWT:
 * 1) verify HS256 bằng SUPABASE_JWT_SECRET (trim)
 * 2) nếu fail → supabase.auth.getUser(jwt) (Auth server verify — tránh lệch secret trên Vercel)
 */
export async function userIdFromSupabaseAccessJwt(
  rawJwt: string
): Promise<string | null> {
  const jwt = rawJwt.trim();
  if (!jwt) return null;

  const jwtSec = (process.env.SUPABASE_JWT_SECRET ?? "").trim();
  if (jwtSec) {
    try {
      const { payload } = await jose.jwtVerify(
        jwt,
        new TextEncoder().encode(jwtSec),
        { algorithms: ["HS256"] }
      );
      if (typeof payload.sub === "string" && payload.sub) {
        return payload.sub;
      }
    } catch {
      /* fallback */
    }
  }

  const { data, error } = await supabase.auth.getUser(jwt);
  if (error || !data.user?.id) return null;
  return data.user.id;
}
