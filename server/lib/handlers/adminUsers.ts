import type { VercelRequest, VercelResponse } from "@vercel/node";
import { supabase } from "../supabase";
import { requireAdminJWT } from "../adminAuth";

/** GET|POST /api/admin/users */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (!(await requireAdminJWT(req, res))) return;

  if (req.method === "GET") {
    try {
      const { data, error } = await supabase.auth.admin.listUsers({
        page: 1,
        perPage: 200,
      });
      if (error) {
        return res.status(500).json({ error: error.message });
      }
      const users = (data?.users ?? []).map((u) => ({
        id: u.id,
        email: u.email,
        created_at: u.created_at,
        last_sign_in_at: u.last_sign_in_at,
      }));
      const ids = users.map((u) => u.id).filter(Boolean);
      let quotaByUser: Record<
        string,
        {
          max_chars: number;
          chars_used: number;
          quota_month: string;
          subscription_expires_at: string | null;
        }
      > = {};
      if (ids.length > 0) {
        let qrows:
          | {
              user_id: string;
              max_chars: number;
              chars_used: number;
              quota_month?: string | null;
              subscription_expires_at?: string | null;
            }[]
          | null = null;
        const q1 = await supabase
          .from("commercial_user_quotas")
          .select(
            "user_id, max_chars, chars_used, quota_month, subscription_expires_at"
          )
          .in("user_id", ids);
        if (!q1.error && q1.data) {
          qrows = q1.data as {
            user_id: string;
            max_chars: number;
            chars_used: number;
            quota_month?: string | null;
            subscription_expires_at?: string | null;
          }[];
        } else if ((q1.error as { code?: string } | null)?.code === "42703") {
          const q2 = await supabase
            .from("commercial_user_quotas")
            .select("user_id, max_chars, chars_used")
            .in("user_id", ids);
          if (!q2.error && q2.data) {
            qrows = (q2.data as { user_id: string; max_chars: number; chars_used: number }[]).map(
              (r) => ({
                ...r,
                quota_month: "",
                subscription_expires_at: null as string | null,
              })
            );
          }
        }
        if (qrows) {
          for (const r of qrows) {
            quotaByUser[r.user_id] = {
              max_chars: Number(r.max_chars ?? 0),
              chars_used: Number(r.chars_used ?? 0),
              quota_month: typeof r.quota_month === "string" ? r.quota_month : "",
              subscription_expires_at:
                r.subscription_expires_at != null
                  ? String(r.subscription_expires_at)
                  : null,
            };
          }
        }
      }
      const usersOut = users.map((u) => {
        const q = quotaByUser[u.id];
        return {
          ...u,
          max_chars: q?.max_chars ?? 0,
          chars_used: q?.chars_used ?? 0,
          quota_month: q?.quota_month ?? "",
          subscription_expires_at: q?.subscription_expires_at ?? null,
        };
      });
      return res.status(200).json({ users: usersOut });
    } catch (e) {
      return res.status(500).json({ error: String(e) });
    }
  }

  if (req.method === "POST") {
    const body = (req.body ?? {}) as {
      email?: string;
      password?: string;
      email_confirm?: boolean;
    };
    const email = typeof body.email === "string" ? body.email.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (!email || !password) {
      return res.status(400).json({ error: "missing_email_or_password" });
    }
    const email_confirm =
      typeof body.email_confirm === "boolean" ? body.email_confirm : true;
    try {
      const { data, error } = await supabase.auth.admin.createUser({
        email,
        password,
        email_confirm,
      });
      if (error) {
        return res.status(400).json({ error: error.message });
      }
      return res.status(201).json({
        user: {
          id: data.user.id,
          email: data.user.email,
          created_at: data.user.created_at,
        },
      });
    } catch (e) {
      return res.status(500).json({ error: String(e) });
    }
  }

  return res.status(405).json({ error: "method not allowed" });
}
