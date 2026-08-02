/**
 * Thêm 1 key proxyxoay.shop vào Supabase (gọi thử API xoay để lấy gateway
 * host:port trước khi insert) — dùng khi cần thêm tay từ CLI/script, tương
 * đương action=add_proxyxoay_keys trên admin panel.
 *
 * Chạy từ thư mục server (có file .env):
 *   node scripts/add-proxyxoay-key.mjs <key> [whitelist_ip]
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(__dirname, "..");
const envPath = path.join(serverRoot, ".env");

function loadDotEnv() {
  if (!fs.existsSync(envPath)) return;
  const raw = fs.readFileSync(envPath, "utf8");
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const eq = t.indexOf("=");
    if (eq <= 0) continue;
    const key = t.slice(0, eq).trim();
    let val = t.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = val;
  }
}

function parseHostPort(s) {
  if (!s) return null;
  const parts = s.split(":");
  if (parts.length < 2) return null;
  const host = (parts[0] ?? "").trim();
  const port = parseInt((parts[1] ?? "").trim(), 10);
  if (!host || Number.isNaN(port) || port <= 0) return null;
  return { host, port };
}

async function main() {
  loadDotEnv();
  const apiKey = process.argv[2];
  const whitelist = process.argv[3] || "";
  if (!apiKey) {
    console.error("Cần truyền key: node scripts/add-proxyxoay-key.mjs <key> [whitelist_ip]");
    process.exit(1);
  }

  const url = process.env.SUPABASE_URL?.replace(/\/$/, "");
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !serviceKey) {
    console.error("Thiếu SUPABASE_URL hoặc SUPABASE_SERVICE_ROLE_KEY (trong .env hoặc env).");
    process.exit(1);
  }

  const rotateUrl =
    `https://proxyxoay.shop/api/get.php?key=${encodeURIComponent(apiKey)}` +
    `&nhamang=random&tinhthanh=0&whitelist=${encodeURIComponent(whitelist)}`;
  console.log("Đang gọi API xoay proxyxoay.shop…");
  const res = await fetch(rotateUrl, { cache: "no-store" });
  const data = await res.json();
  console.log("Response:", JSON.stringify(data));

  const status = Number(data.status ?? 0);
  if (status !== 100) {
    console.error(`Xoay thất bại — status=${status}, message=${data.message ?? data.comen ?? ""}`);
    process.exit(1);
  }
  const http = parseHostPort(data.proxyhttp);
  const socks = parseHostPort(data.proxysocks5) ?? http;
  if (!http) {
    console.error("Response thiếu proxyhttp hợp lệ.");
    process.exit(1);
  }

  const packageExpires = new Date();
  packageExpires.setUTCMonth(packageExpires.getUTCMonth() + 1);

  const row = {
    label: `proxyxoay-${http.host}-${http.port}`,
    http_host: http.host,
    http_port: http.port,
    socks_host: socks.host,
    socks_port: socks.port,
    username: "",
    password: "",
    api_key: apiKey,
    app_id: "",
    source: "proxyxoay",
    is_active: true,
    last_rotated_at: "2020-01-01T00:00:00Z",
    package_expires_at: packageExpires.toISOString(),
  };

  const insertRes = await fetch(`${url}/rest/v1/proxies`, {
    method: "POST",
    headers: {
      apikey: serviceKey,
      Authorization: `Bearer ${serviceKey}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
    },
    body: JSON.stringify(row),
  });
  if (!insertRes.ok) {
    const body = await insertRes.text();
    console.error(`Insert lỗi HTTP ${insertRes.status}:`, body.slice(0, 800));
    process.exit(1);
  }
  const inserted = await insertRes.json();
  console.log("Đã thêm proxy:", JSON.stringify(inserted, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
