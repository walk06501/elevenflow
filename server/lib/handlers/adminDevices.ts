import type { VercelRequest, VercelResponse } from "@vercel/node";
import { supabase } from "../supabase";
import { requireAdminJWT } from "../adminAuth";

/** user_id từ query — rewrite Vercel có thể ghi đè query nên fallback parse req.url. */
function userIdFromDevicesGet(req: VercelRequest): string {
  const q = req.query.user_id;
  if (typeof q === "string" && q.trim()) return q.trim();
  if (Array.isArray(q) && q.length > 0 && typeof q[0] === "string" && q[0].trim()) {
    return q[0].trim();
  }
  const raw = req.url || "";
  const qi = raw.indexOf("?");
  if (qi >= 0) {
    try {
      const u = new URL(raw, "http://localhost");
      const v = u.searchParams.get("user_id");
      if (v?.trim()) return v.trim();
    } catch {
      /* */
    }
  }
  return "";
}

async function listDevicesForUser(uid: string, res: VercelResponse) {
  try {
    const { data, error } = await supabase
      .from("licensed_devices")
      .select("id, device_fingerprint, created_at")
      .eq("user_id", uid)
      .order("created_at", { ascending: true });
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    return res.status(200).json({ devices: data ?? [] });
  } catch (e) {
    return res.status(500).json({ error: String(e) });
  }
}

/** GET|POST /api/admin/devices */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (!(await requireAdminJWT(req, res))) return;

  if (req.method === "GET") {
    const uid = userIdFromDevicesGet(req);
    if (!uid) {
      return res.status(400).json({ error: "missing_user_id_query" });
    }
    return listDevicesForUser(uid, res);
  }

  if (req.method === "POST") {
    const body = (req.body ?? {}) as {
      action?: string;
      user_id?: string;
    };
    // Trang admin dùng POST list (body) — tránh mất ?user_id= do rewrite Vercel.
    if (body.action === "list") {
      const uid =
        typeof body.user_id === "string" ? body.user_id.trim() : "";
      if (!uid) {
        return res.status(400).json({ error: "missing_user_id" });
      }
      return listDevicesForUser(uid, res);
    }
    if (body.action !== "reset_all") {
      return res.status(400).json({ error: "unknown_action" });
    }
    const userId =
      typeof body.user_id === "string" ? body.user_id.trim() : "";
    if (!userId) {
      return res.status(400).json({ error: "missing_user_id" });
    }
    try {
      const { error } = await supabase
        .from("licensed_devices")
        .delete()
        .eq("user_id", userId);
      if (error) {
        return res.status(500).json({ error: error.message });
      }
      return res.status(200).json({ ok: true });
    } catch (e) {
      return res.status(500).json({ error: String(e) });
    }
  }

  return res.status(405).json({ error: "method not allowed" });
}
