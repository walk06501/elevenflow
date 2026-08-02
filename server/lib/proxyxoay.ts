/**
 * Client cho API xoay IP của proxyxoay.shop (nguồn backup thứ 2, xoay theo
 * API giống 1ip.vn — khác Webshare vì Webshare không có API đổi IP).
 *
 * Đã test thật với 1 key mẫu (xem log triển khai) — endpoint:
 *   GET https://proxyxoay.shop/api/get.php?key=...&nhamang=random&tinhthanh=0&whitelist=
 * Response mẫu (status=100 thành công):
 *   { "status":100, "message":"proxy nay se die sau 1318s",
 *     "proxyhttp":"160.250.166.34:10184::", "proxysocks5":"160.250.166.34:11184::",
 *     "Nha Mang":"fpt", "Vi Tri":"QuangNinh1", "Token expiration date":"...", "ip":"..." }
 * "proxyhttp"/"proxysocks5" dạng "host:port::" — 2 trường cuối (user/pass) RỖNG,
 * xác thực theo whitelist IP hoặc theo phiên do vendor quản lý, không cần
 * username/password như 1ip.vn/Webshare.
 *
 * Gateway host:port ("Proxy Trung Gian") theo quan sát ổn định cho 1 key khi
 * gọi lại nhiều lần — NHƯNG vẫn cập nhật lại http_host/http_port/socks_host/
 * socks_port trong DB sau MỖI lần xoay để tự "chữa lành" nếu vendor đổi
 * gateway ngầm (không tin tưởng tuyệt đối là bất biến như 1ip.vn).
 *
 * status=101: key không tồn tại. status=102: hết tiền/hết hạn. Cả 2 coi là
 * "key chết vĩnh viễn" → adminProxies/proxyLease tự xoá key khỏi DB (yêu cầu
 * người dùng). status khác (103 hết hàng, 104 lỗi không xác định, lỗi mạng)
 * → lỗi tạm thời, thử lại sau, KHÔNG xoá key.
 */

export interface ProxyxoayRotateResult {
  ok: boolean;
  /** true khi key chết vĩnh viễn (status 101/102) — nên xoá khỏi DB, không thử lại. */
  dead: boolean;
  waitSeconds: number;
  message: string;
  httpHost?: string;
  httpPort?: number;
  socksHost?: string;
  socksPort?: number;
  /** Số giây còn lại trước khi phiên proxy tự die (parse từ message), không bắt buộc dùng. */
  ttlSeconds?: number;
}

interface ProxyxoayApiResponse {
  status?: number;
  message?: string;
  comen?: string;
  proxyhttp?: string;
  proxysocks5?: string;
  [k: string]: unknown;
}

/** Parse "host:port" hoặc "host:port::" (2 trường user/pass cuối rỗng, bỏ qua). */
function parseHostPort(s: string | undefined): { host: string; port: number } | null {
  if (!s) return null;
  const parts = s.split(":");
  if (parts.length < 2) return null;
  const host = (parts[0] ?? "").trim();
  const port = parseInt((parts[1] ?? "").trim(), 10);
  if (!host || Number.isNaN(port) || port <= 0) return null;
  return { host, port };
}

const DEFAULT_WAIT_SECONDS = 20;
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

export async function rotateProxyxoay(
  apiKey: string,
  whitelist = ""
): Promise<ProxyxoayRotateResult> {
  const url =
    `https://proxyxoay.shop/api/get.php?key=${encodeURIComponent(apiKey)}` +
    `&nhamang=random&tinhthanh=0&whitelist=${encodeURIComponent(whitelist)}`;

  let data: ProxyxoayApiResponse;
  try {
    const res = await fetchWithTimeout(url, FETCH_TIMEOUT_MS);
    data = (await res.json()) as ProxyxoayApiResponse;
  } catch (e) {
    return {
      ok: false,
      dead: false,
      waitSeconds: DEFAULT_WAIT_SECONDS,
      message: String((e as Error)?.message ?? e),
    };
  }

  const status = Number(data.status ?? 0);
  const msg = data.message || data.comen || "";

  if (status === 100) {
    const http = parseHostPort(data.proxyhttp);
    const socks = parseHostPort(data.proxysocks5) ?? http;
    if (!http) {
      return {
        ok: false,
        dead: false,
        waitSeconds: DEFAULT_WAIT_SECONDS,
        message: "proxyxoay: response thiếu proxyhttp hợp lệ",
      };
    }
    const ttlMatch = msg.match(/(\d+)\s*s\b/i);
    return {
      ok: true,
      dead: false,
      waitSeconds: 0,
      message: msg,
      httpHost: http.host,
      httpPort: http.port,
      socksHost: (socks ?? http).host,
      socksPort: (socks ?? http).port,
      ttlSeconds: ttlMatch ? parseInt(ttlMatch[1]!, 10) : undefined,
    };
  }

  if (status === 101 || status === 102) {
    return { ok: false, dead: true, waitSeconds: 0, message: msg || `status=${status}` };
  }

  return {
    ok: false,
    dead: false,
    waitSeconds: DEFAULT_WAIT_SECONDS,
    message: msg || `status=${status}`,
  };
}

/** Gọi thử API để kiểm tra key còn sống không (admin Recheck). */
export async function probeProxyxoayKey(
  apiKey: string,
  whitelist = ""
): Promise<{ alive: boolean; message: string }> {
  const r = await rotateProxyxoay(apiKey, whitelist);
  if (r.ok) return { alive: true, message: r.message || "ok" };
  if (r.dead) return { alive: false, message: r.message };
  return { alive: true, message: r.message || "recheck_inconclusive_treated_alive" };
}
