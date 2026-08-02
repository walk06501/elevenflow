/**
 * Đồng bộ NGAY 1 link Webshare cụ thể vào Supabase (không cần chờ deploy
 * Vercel / không cần WEBSHARE_LIST_URLS đã cập nhật) — dùng khi cần thêm
 * gấp 1 plan mới trong lúc CLI Vercel chưa đăng nhập lại được.
 *
 * Chạy từ thư mục server (có file .env):
 *   node scripts/sync-one-webshare-link.mjs "<url>"
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

function parseWebshareList(text) {
  const out = [];
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

async function main() {
  loadDotEnv();
  const url = process.argv[2];
  if (!url) {
    console.error('Cần truyền URL: node scripts/sync-one-webshare-link.mjs "<url>"');
    process.exit(1);
  }
  const supaUrl = process.env.SUPABASE_URL?.replace(/\/$/, "");
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supaUrl || !serviceKey) {
    console.error("Thiếu SUPABASE_URL hoặc SUPABASE_SERVICE_ROLE_KEY (trong .env hoặc env).");
    process.exit(1);
  }

  console.log("Đang tải list Webshare…");
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) {
    console.error(`HTTP ${res.status} khi tải list.`);
    process.exit(1);
  }
  const text = await res.text();
  const entries = parseWebshareList(text);
  console.log(`Parse được ${entries.length} proxy.`);
  if (entries.length === 0) {
    console.error("Không có proxy nào — kiểm tra lại link.");
    process.exit(1);
  }

  const rows = entries.map((e) => ({
    host: e.host,
    port: e.port,
    username: e.username,
    password: e.password,
    label: `webshare-${e.host}-${e.port}`,
  }));

  const CHUNK = 200;
  let upserted = 0;
  for (let i = 0; i < rows.length; i += CHUNK) {
    const chunk = rows.slice(i, i + CHUNK);
    const rpcRes = await fetch(`${supaUrl}/rest/v1/rpc/upsert_webshare_proxies`, {
      method: "POST",
      headers: {
        apikey: serviceKey,
        Authorization: `Bearer ${serviceKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ p_rows: chunk }),
    });
    if (!rpcRes.ok) {
      const body = await rpcRes.text();
      console.error(`upsert_webshare_proxies lỗi HTTP ${rpcRes.status}:`, body.slice(0, 800));
      process.exit(1);
    }
    const n = await rpcRes.json();
    upserted += typeof n === "number" ? n : chunk.length;
    console.log(`  chunk ${i}-${i + chunk.length}: OK`);
  }

  console.log(`\nOK: upsert tổng ${upserted}/${rows.length} proxy từ link này vào Supabase.`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
