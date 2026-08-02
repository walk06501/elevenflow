import type { VercelRequest, VercelResponse } from "@vercel/node";
import { supabase } from "../supabase";
import { requireAdminJWT } from "../adminAuth";

/** POST /api/admin/user-delete */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (!(await requireAdminJWT(req, res))) return;
  if (req.method !== "POST") {
    return res.status(405).json({ error: "method not allowed" });
  }
  const body = (req.body ?? {}) as { user_id?: string };
  const userId = typeof body.user_id === "string" ? body.user_id.trim() : "";
  if (!userId) {
    return res.status(400).json({ error: "missing_user_id" });
  }
  try {
    const { error } = await supabase.auth.admin.deleteUser(userId);
    if (error) {
      return res.status(400).json({ error: error.message });
    }
    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: String(e) });
  }
}
