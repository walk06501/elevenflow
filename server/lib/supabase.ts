import { createClient } from "@supabase/supabase-js";

if (!process.env.SUPABASE_URL) throw new Error("SUPABASE_URL is required");
if (!process.env.SUPABASE_SERVICE_ROLE_KEY)
  throw new Error("SUPABASE_SERVICE_ROLE_KEY is required");

export const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

export interface Proxy {
  id: number;
  label: string;
  http_host: string;
  http_port: number;
  socks_host: string;
  socks_port: number;
  username: string;
  password: string;
  api_key: string;
  app_id: string;
  last_rotated_at: string;
  is_active: boolean;
  /** Hết hạn gói proxy (migration 010); null = không khóa theo ngày. */
  package_expires_at?: string | null;
  last_api_check_at?: string | null;
  last_api_check_ok?: boolean | null;
  last_api_check_msg?: string | null;
  // Lease state — added in migration 002.
  leased_by: string | null;
  leased_at: string | null;
  lease_token: string | null;
  /** migration 011: 'legacy' (1ip.vn, có changeip) | 'webshare' (đồng bộ định kỳ, không changeip). */
  source?: string | null;
  /** migration 011: lần gần nhất đồng bộ Webshare còn thấy dòng này. */
  last_seen_at?: string | null;
  /** migration 013: pool-wide ban cooldown — không session nào lease được trước mốc này. */
  banned_until?: string | null;
  /** migration 013: số lần bị site đích ban gần đây (cửa sổ trượt 24h). */
  ban_count?: number | null;
  last_banned_at?: string | null;
  /** migration 018: số lần đã lease liên tiếp kể từ lần tự nghỉ gần nhất (chỉ webshare). */
  use_count?: number | null;
}

export function toHTTPUrl(p: Proxy): string {
  return `http://${p.username}:${p.password}@${p.http_host}:${p.http_port}`;
}

export function toSOCKS5Url(p: Proxy): string {
  return `socks5://${p.username}:${p.password}@${p.socks_host}:${p.socks_port}`;
}

/** Pick proxy rotated longest ago (round-robin effect). */
export async function pickProxy(): Promise<Proxy | null> {
  const nowIso = new Date().toISOString();
  let { data, error } = await supabase
    .from("proxies")
    .select("*")
    .eq("is_active", true)
    .or(`package_expires_at.is.null,package_expires_at.gt.${nowIso}`)
    .order("last_rotated_at", { ascending: true })
    .limit(1)
    .single();
  if (
    error &&
    ((error as { code?: string }).code === "42703" ||
      String(error.message).includes("package_expires_at"))
  ) {
    const r2 = await supabase
      .from("proxies")
      .select("*")
      .eq("is_active", true)
      .order("last_rotated_at", { ascending: true })
      .limit(1)
      .single();
    data = r2.data;
    error = r2.error;
  }
  if (error || !data) return null;
  return data as Proxy;
}

export async function markRotated(id: number): Promise<void> {
  await supabase
    .from("proxies")
    .update({ last_rotated_at: new Date().toISOString() })
    .eq("id", id);
}

/**
 * updateProxyEndpoint: cập nhật lại host:port sau khi gọi API xoay của nguồn
 * proxyxoay.shop (migration 014) — gateway trả về CÙNG lúc với response xoay,
 * khác 1ip.vn (host:port cố định từ lúc add, chỉ IP nền thay đổi ngầm).
 */
export async function updateProxyEndpoint(
  id: number,
  endpoint: { httpHost: string; httpPort: number; socksHost: string; socksPort: number }
): Promise<void> {
  await supabase
    .from("proxies")
    .update({
      http_host: endpoint.httpHost,
      http_port: endpoint.httpPort,
      socks_host: endpoint.socksHost,
      socks_port: endpoint.socksPort,
    })
    .eq("id", id);
}

/** deleteProxyById: xoá vĩnh viễn 1 dòng proxy (dùng khi key proxyxoay hết hạn/không tồn tại). */
export async function deleteProxyById(id: number): Promise<void> {
  await supabase.from("proxies").delete().eq("id", id);
}

/**
 * pickAndLease: gọi RPC atomic pick_and_lease_proxy.
 *  - Trả Proxy row (đã claim cho sessionId) HOẶC null nếu không còn slot.
 *  - excludeUrl: URL vừa bị ban — server đảm bảo không cấp lại cùng URL.
 *  - maxLeases: tối đa số row leased đồng thời cho session_id (migration 003).
 *  - Không tự nghỉ theo số lần dùng (đã bỏ migration 018 → 019). Ban chỉ khi
 *    client release banned=true (site thật sự chặn IP).
 */
export async function pickAndLease(
  sessionId: string,
  excludeUrl?: string,
  maxLeases: number = 3
): Promise<Proxy | null> {
  const { data, error } = await supabase.rpc("pick_and_lease_proxy", {
    p_session_id: sessionId,
    p_exclude_url: excludeUrl ?? null,
    p_max_leases: maxLeases,
  });
  if (error) throw new Error("supabase pick_and_lease_proxy: " + error.message);
  if (!data || data.length === 0) return null;
  return data[0] as Proxy;
}

/** Đếm số proxy đang leased_by session (phân biệt wait vì cap vs hết pool). */
export async function countSessionLeases(sessionId: string): Promise<number> {
  const { count, error } = await supabase
    .from("proxies")
    .select("*", { count: "exact", head: true })
    .eq("leased_by", sessionId);
  if (error) throw new Error("countSessionLeases: " + error.message);
  return count ?? 0;
}

/**
 * Đếm số dòng proxy có thể được pick_and_lease (is_active + chưa hết hạn gói).
 * Dùng client autoscale NumWorkers — không phụ thuộc leased_by (pool capacity).
 */
export async function countLeaseablePoolProxies(): Promise<number> {
  const nowIso = new Date().toISOString();
  let { count, error } = await supabase
    .from("proxies")
    .select("*", { count: "exact", head: true })
    .eq("is_active", true)
    .or(`package_expires_at.is.null,package_expires_at.gt.${nowIso}`);
  if (
    error &&
    ((error as { code?: string }).code === "42703" ||
      String(error.message).includes("package_expires_at"))
  ) {
    const r2 = await supabase
      .from("proxies")
      .select("*", { count: "exact", head: true })
      .eq("is_active", true);
    count = r2.count;
    error = r2.error;
  }
  if (error) throw new Error("countLeaseablePoolProxies: " + error.message);
  return count ?? 0;
}

/** Số giây ngắn nhất đến khi có proxy free + hết cooldown. */
export async function nextLeaseEtaSeconds(): Promise<number> {
  const { data, error } = await supabase.rpc("next_lease_eta_seconds");
  if (error || data == null) return 60;
  return Math.max(1, Number(data));
}

/**
 * releaseLease: free 1 lease cho session (RPC release_proxy_lease, migration
 * 013 + 016 + 017). Chỉ release đúng record có (lease_token, leased_by) khớp
 * — chống stale release từ session khác.
 *  - banned=true + nguồn webshare (IP tĩnh): áp cooldown LUỸ TIẾN pool-wide
 *    theo ban_count — lần 1 ngắn (PROXY_BAN_COOLDOWN_TIER1_MINUTES, mặc định
 *    15 phút), lần 2 vừa (PROXY_BAN_COOLDOWN_TIER2_MINUTES, mặc định 180 =
 *    3 giờ), lần 3+ dùng PROXY_BAN_COOLDOWN_MINUTES (mặc định 1440 = 1 ngày)
 *    NHƯNG đồng thời tự is_active=false (nghỉ hưu hẳn) khi chạm
 *    PROXY_BAN_MAX_STRIKES lần trong PROXY_BAN_STRIKE_WINDOW_HOURS giờ (mặc
 *    định 168 = 7 ngày). Cooldown luỹ tiến tránh tình trạng cả pool bị khoá
 *    đồng thời khi tỷ lệ ban cao hơn tỷ lệ hồi phục (xem migration 017).
 *  - banned=true + nguồn proxyxoay (gateway tự đổi IP mỗi lần lease): RPC tự
 *    bỏ qua cooldown/ban_count cho nguồn này — release bình thường.
 *  - banned=false: free ngay, không đụng banned_until/ban_count.
 */
export async function releaseLease(
  sessionId: string,
  leaseToken: string,
  banned = false
): Promise<void> {
  const cooldownMinutes = Math.max(
    1,
    parseInt(process.env.PROXY_BAN_COOLDOWN_MINUTES ?? "1440", 10) || 1440
  );
  const maxStrikes = Math.max(
    1,
    parseInt(process.env.PROXY_BAN_MAX_STRIKES ?? "3", 10) || 3
  );
  const strikeWindowHours = Math.max(
    1,
    parseInt(process.env.PROXY_BAN_STRIKE_WINDOW_HOURS ?? "168", 10) || 168
  );
  const cooldownTier1Minutes = Math.max(
    1,
    parseInt(process.env.PROXY_BAN_COOLDOWN_TIER1_MINUTES ?? "15", 10) || 15
  );
  const cooldownTier2Minutes = Math.max(
    1,
    parseInt(process.env.PROXY_BAN_COOLDOWN_TIER2_MINUTES ?? "180", 10) || 180
  );
  const { error } = await supabase.rpc("release_proxy_lease", {
    p_session_id: sessionId,
    p_lease_token: leaseToken,
    p_banned: banned,
    p_cooldown_minutes: cooldownMinutes,
    p_max_strikes: maxStrikes,
    p_strike_window_hours: strikeWindowHours,
    p_cooldown_tier1_minutes: cooldownTier1Minutes,
    p_cooldown_tier2_minutes: cooldownTier2Minutes,
  });
  if (error) throw new Error("supabase release_proxy_lease: " + error.message);
}

/**
 * heartbeat: cập nhật leased_at = now() cho danh sách lease_token (đảm bảo
 * khớp session). Dùng để chống zombie cleanup khi worker đang chạy chunk
 * dài (>90s) mà chưa release.
 */
export async function heartbeat(
  sessionId: string,
  leaseTokens: string[]
): Promise<number> {
  if (leaseTokens.length === 0) return 0;
  const { data, error } = await supabase
    .from("proxies")
    .update({ leased_at: new Date().toISOString() })
    .in("lease_token", leaseTokens)
    .eq("leased_by", sessionId)
    .select("id");
  if (error) throw new Error("supabase heartbeat: " + error.message);
  return data?.length ?? 0;
}
