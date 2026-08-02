/**
 * Nguồn proxy dự phòng: Webshare (proxy.webshare.io), chạy SONG SONG với pool
 * 1ip.vn cũ (source='legacy'). Webshare direct-mode không có API đổi IP theo
 * request — mỗi dòng là 1 IP:port cố định, HTTP & SOCKS5 dùng CÙNG host:port
 * (theo tài liệu Webshare "Proxy Connection"). Vì vậy các dòng nhập từ đây
 * lưu api_key='' để server (proxyLease/proxyRotate) tự bỏ qua bước changeip
 * 1ip.vn + bỏ cooldown 60s (migration 011) → lease/xoay IP nhanh nhất.
 *
 * Danh sách proxy bên Webshare cập nhật thường xuyên (họ tự thay IP chết) →
 * phải GỌI LẠI API để lấy list mới; không cache tĩnh trong code. Đồng bộ định
 * kỳ qua /api/cron/sync-proxies (vercel.json crons) hoặc tay qua admin panel
 * (action=sync_webshare).
 */

import { supabase } from "./supabase";

export interface WebshareProxyEntry {
  host: string;
  port: number;
  username: string;
  password: string;
}

/** Đọc danh sách URL download (Proxy List API v2, mode=direct) từ env, phân tách bằng dấu phẩy hoặc xuống dòng. */
export function webshareListUrlsFromEnv(): string[] {
  const raw = process.env.WEBSHARE_LIST_URLS ?? "";
  return raw
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Parse định dạng plain text Webshare trả về khi download:
 *   ip:port:username:password  (mỗi dòng 1 proxy)
 * Mật khẩu có thể chứa ký tự ":" → chỉ tách 3 dấu ":" đầu, phần còn lại là password.
 */
export function parseWebshareList(text: string): WebshareProxyEntry[] {
  const out: WebshareProxyEntry[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const i1 = line.indexOf(":");
    if (i1 <= 0) continue;
    const i2 = line.indexOf(":", i1 + 1);
    if (i2 <= i1 + 1) continue;
    const i3 = line.indexOf(":", i2 + 1);
    if (i3 <= i2 + 1) continue;
    const host = line.slice(0, i1).trim();
    const portStr = line.slice(i1 + 1, i2).trim();
    const username = line.slice(i2 + 1, i3).trim();
    const password = line.slice(i3 + 1).trim();
    const port = parseInt(portStr, 10);
    if (!host || Number.isNaN(port) || port <= 0 || !username || !password) continue;
    out.push({ host, port, username, password });
  }
  return out;
}

const FETCH_TIMEOUT_MS = 15_000;

async function fetchWithTimeout(url: string, ms: number): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { cache: "no-store", signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

export async function fetchWebshareList(url: string): Promise<WebshareProxyEntry[]> {
  const res = await fetchWithTimeout(url, FETCH_TIMEOUT_MS);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  const text = await res.text();
  return parseWebshareList(text);
}

export interface WebshareSyncResult {
  ok: boolean;
  urls_total: number;
  urls_ok: number;
  urls_failed: { url: string; error: string }[];
  fetched: number;
  upserted: number;
  deactivated_stale: number;
}

/** Ẩn phần cuối token trong URL khi log lỗi (không lộ nguyên link tải proxy). */
function redactUrl(url: string): string {
  try {
    const u = new URL(url);
    const parts = u.pathname.split("/").filter(Boolean);
    const masked = parts.map((p, i) => (i === 1 && p.length > 8 ? p.slice(0, 6) + "…" : p));
    return u.origin + "/" + masked.join("/");
  } catch {
    return "(url không hợp lệ)";
  }
}

/**
 * syncWebshareProxies: gọi tất cả URL Webshare TRONG CÙNG LÚC (Promise.all —
 * tối đa tốc độ, không chờ tuần tự), gộp + khử trùng entries, rồi upsert 1
 * lần vào bảng proxies (source='webshare'). Dòng cũ không còn xuất hiện
 * trong lần sync này (Webshare đã thay IP khác) → is_active=false.
 */
export async function syncWebshareProxies(): Promise<WebshareSyncResult> {
  const urls = webshareListUrlsFromEnv();
  const result: WebshareSyncResult = {
    ok: true,
    urls_total: urls.length,
    urls_ok: 0,
    urls_failed: [],
    fetched: 0,
    upserted: 0,
    deactivated_stale: 0,
  };
  if (urls.length === 0) {
    result.ok = false;
    return result;
  }

  const settled = await Promise.allSettled(urls.map((u) => fetchWebshareList(u)));
  const merged = new Map<string, WebshareProxyEntry>();
  for (let i = 0; i < settled.length; i++) {
    const s = settled[i]!;
    if (s.status === "fulfilled") {
      result.urls_ok++;
      for (const e of s.value) {
        merged.set(`${e.host}:${e.port}:${e.username}`, e);
      }
    } else {
      result.urls_failed.push({
        url: redactUrl(urls[i]!),
        error: String((s.reason as Error)?.message ?? s.reason),
      });
    }
  }
  result.fetched = merged.size;
  if (merged.size === 0) {
    result.ok = result.urls_ok > 0; // urls sống nhưng rỗng vẫn coi là ok (không xoá gì)
    return result;
  }

  const rows = Array.from(merged.values()).map((e) => ({
    host: e.host,
    port: e.port,
    username: e.username,
    password: e.password,
    label: `webshare-${e.host}-${e.port}`,
  }));

  // RPC upsert_webshare_proxies (migration 012) — 1 round-trip/chunk, xử lý
  // ĐÚNG insert vs update ngay trong Postgres: dòng MỚI được set
  // last_rotated_at='1970-01-01' (lease được ngay), dòng ĐÃ CÓ giữ nguyên
  // last_rotated_at (không phá LRU/cooldown đang chạy). Không dùng
  // supabase-js .upsert() trực tiếp vì nó không phân biệt được insert/update
  // cho cột này (cột có DEFAULT now() ở DB → dòng mới bị coi là "vừa rotate",
  // sắp xếp SAU proxy legacy cũ hơn → chọn nhầm proxy legacy đang chết).
  const CHUNK = 200;
  for (let i = 0; i < rows.length; i += CHUNK) {
    const chunk = rows.slice(i, i + CHUNK);
    const { error, data } = await supabase.rpc("upsert_webshare_proxies", {
      p_rows: chunk,
    });
    if (error) {
      throw new Error("upsert_webshare_proxies: " + error.message);
    }
    result.upserted += typeof data === "number" ? data : chunk.length;
  }

  // Tắt các dòng webshare cũ không còn xuất hiện trong lần sync này (Webshare
  // đã thay bằng IP khác) — tránh app cố lease vào IP đã chết bên nhà cung cấp.
  const { data: existing, error: exErr } = await supabase
    .from("proxies")
    .select("id, http_host, http_port, username")
    .eq("source", "webshare")
    .eq("is_active", true);
  if (exErr) {
    throw new Error("list existing webshare proxies: " + exErr.message);
  }
  const staleIds = (existing ?? [])
    .filter((r) => !merged.has(`${r.http_host}:${r.http_port}:${r.username}`))
    .map((r) => r.id as number);
  if (staleIds.length > 0) {
    const { error: deErr } = await supabase
      .from("proxies")
      .update({ is_active: false })
      .in("id", staleIds);
    if (deErr) {
      throw new Error("deactivate stale webshare proxies: " + deErr.message);
    }
    result.deactivated_stale = staleIds.length;
  }

  result.ok = result.urls_ok > 0;
  return result;
}
