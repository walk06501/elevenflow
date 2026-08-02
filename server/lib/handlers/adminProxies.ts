import type { VercelRequest, VercelResponse } from "@vercel/node";
import { supabase } from "../supabase";
import { requireAdminJWT } from "../adminAuth";
import { syncWebshareProxies } from "../webshare";
import { rotateProxyxoay, probeProxyxoayKey } from "../proxyxoay";

async function deactivateExpiredPackages(): Promise<void> {
  const now = new Date().toISOString();
  const { error } = await supabase
    .from("proxies")
    .update({ is_active: false })
    .not("package_expires_at", "is", null)
    .lte("package_expires_at", now)
    .eq("is_active", true);
  if (error && (error as { code?: string }).code === "42703") {
    return;
  }
  if (error) {
    console.warn("deactivateExpiredPackages:", error.message);
  }
}

function expiresAfterOneCalendarMonth(): string {
  const d = new Date();
  d.setUTCMonth(d.getUTCMonth() + 1);
  return d.toISOString();
}

/** GET|POST /api/admin/proxies — GET danh sách; POST sync_webshare | add_proxyxoay_keys | recheck | … */
export default async function adminProxies(
  req: VercelRequest,
  res: VercelResponse
) {
  if (!(await requireAdminJWT(req, res))) return;

  if (req.method === "GET") {
    await deactivateExpiredPackages();
    const { data, error } = await supabase
      .from("proxies")
      .select("*")
      .order("id", { ascending: true });
    if (error) {
      if ((error as { code?: string }).code === "42703") {
        return res.status(500).json({
          error: "proxies_missing_columns",
          hint: "Chạy migration server/migrations/010_proxies_package_expiry.sql trên Supabase.",
        });
      }
      return res.status(500).json({ error: error.message });
    }
    return res.status(200).json({ proxies: data ?? [] });
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "method not allowed" });
  }

  const body = (req.body ?? {}) as {
    action?: string;
    proxy_id?: number;
    days?: number;
    is_active?: boolean;
    /** action=add_proxyxoay_keys: mỗi dòng 1 key (tuỳ chọn "key|whitelist_ip"). */
    keys?: string[];
  };
  const action = typeof body.action === "string" ? body.action.trim() : "";

  if (action === "sync_webshare") {
    try {
      const result = await syncWebshareProxies();
      return res.status(result.ok ? 200 : 502).json(result);
    } catch (e) {
      return res.status(500).json({ error: String((e as Error)?.message ?? e) });
    }
  }

  // Thêm key proxyxoay.shop (nguồn backup, xoay theo API get.php — xem
  // proxyxoay.ts). Mỗi dòng: "key" hoặc "key|whitelist_ip". Gọi thử API
  // ngay để lấy host:port gateway ban đầu — key lỗi/chết bị báo lại,
  // không insert (http_host/http_port là NOT NULL).
  if (action === "add_proxyxoay_keys") {
    const lines = Array.isArray(body.keys) ? body.keys : [];
    if (lines.length === 0) {
      return res.status(400).json({ error: "missing_keys", hint: "Gửi { keys: [\"key1\", \"key2|1.2.3.4\", ...] }" });
    }
    const packageExpires = expiresAfterOneCalendarMonth();
    let inserted_count = 0;
    const errors: string[] = [];
    for (let i = 0; i < lines.length; i++) {
      const raw = (lines[i] ?? "").trim();
      if (!raw || raw.startsWith("#")) continue;
      const [keyPart, whitelistPart] = raw.split("|").map((s) => s.trim());
      const apiKey = keyPart ?? "";
      if (!apiKey) {
        errors.push(`Dòng ${i + 1}: thiếu key`);
        continue;
      }
      const result = await rotateProxyxoay(apiKey, whitelistPart ?? "");
      if (!result.ok || !result.httpHost || !result.httpPort) {
        errors.push(`Dòng ${i + 1} (key ${apiKey.slice(0, 6)}…): ${result.message || "xoay thất bại"}`);
        continue;
      }
      const { error } = await supabase.from("proxies").insert({
        label: `proxyxoay-${result.httpHost}-${result.httpPort}`,
        http_host: result.httpHost,
        http_port: result.httpPort,
        socks_host: result.socksHost || result.httpHost,
        socks_port: result.socksPort || result.httpPort,
        username: "",
        password: "",
        api_key: apiKey,
        app_id: "",
        source: "proxyxoay",
        is_active: true,
        last_rotated_at: "2020-01-01T00:00:00Z",
        package_expires_at: packageExpires,
      });
      if (error) {
        errors.push(`Dòng ${i + 1}: ${error.message}`);
        continue;
      }
      inserted_count++;
      await new Promise((res2) => setTimeout(res2, 300));
    }
    return res.status(200).json({ ok: true, inserted_count, errors });
  }

  // Recheck: chỉ còn nguồn proxyxoay có API kiểm tra (1ip.vn đã bị xoá hẳn —
  // migration 015). Webshare không có API kiểm tra riêng — bỏ qua.
  if (action === "recheck") {
    await deactivateExpiredPackages();
    const { data: rows, error } = await supabase
      .from("proxies")
      .select("id, api_key")
      .eq("source", "proxyxoay")
      .not("api_key", "is", null)
      .neq("api_key", "")
      .order("id", { ascending: true });
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    const results: { id: number; alive: boolean; message: string }[] = [];
    for (const r of rows ?? []) {
      const apiKey = String(r.api_key ?? "");
      const pr = await probeProxyxoayKey(apiKey);
      if (!pr.alive) {
        // Key proxyxoay chết (status 101/102) → xoá thẳng khỏi DB theo yêu cầu.
        await supabase.from("proxies").delete().eq("id", r.id);
        results.push({ id: r.id, alive: false, message: pr.message + " (đã xoá key)" });
        await new Promise((res2) => setTimeout(res2, 350));
        continue;
      }
      await supabase
        .from("proxies")
        .update({
          last_api_check_at: new Date().toISOString(),
          last_api_check_ok: true,
          last_api_check_msg: pr.message.slice(0, 500),
        })
        .eq("id", r.id);
      results.push({ id: r.id, alive: true, message: pr.message });
      await new Promise((res2) => setTimeout(res2, 350));
    }
    return res.status(200).json({ ok: true, results });
  }

  if (action === "extend_package") {
    const id = Number(body.proxy_id);
    const days = Math.min(365, Math.max(1, Number(body.days) || 30));
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: "missing_proxy_id" });
    }
    const { data: row, error: gerr } = await supabase
      .from("proxies")
      .select("package_expires_at")
      .eq("id", id)
      .maybeSingle();
    if (gerr) {
      return res.status(500).json({ error: gerr.message });
    }
    if (!row) {
      return res.status(404).json({ error: "proxy_not_found" });
    }
    const now = Date.now();
    const cur = row.package_expires_at
      ? new Date(String(row.package_expires_at)).getTime()
      : now;
    const base = Math.max(cur, now);
    const nu = new Date(base);
    nu.setUTCDate(nu.getUTCDate() + days);
    const { error } = await supabase
      .from("proxies")
      .update({
        package_expires_at: nu.toISOString(),
        is_active: true,
      })
      .eq("id", id);
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    return res.status(200).json({ ok: true, package_expires_at: nu.toISOString() });
  }

  if (action === "set_active") {
    const id = Number(body.proxy_id);
    const active = Boolean(body.is_active);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: "missing_proxy_id" });
    }
    const { error } = await supabase
      .from("proxies")
      .update({ is_active: active })
      .eq("id", id);
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    return res.status(200).json({ ok: true });
  }

  if (action === "delete") {
    const id = Number(body.proxy_id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: "missing_proxy_id" });
    }
    const { error } = await supabase.from("proxies").delete().eq("id", id);
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    return res.status(200).json({ ok: true });
  }

  return res.status(400).json({ error: "unknown_action" });
}
