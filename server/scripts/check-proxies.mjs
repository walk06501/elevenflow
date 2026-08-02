/**
 * Liệt kê bảng public.proxies qua Supabase REST (service role).
 *
 * Chạy từ thư mục server (có file .env):
 *   node scripts/check-proxies.mjs
 *
 * Hoặc chỉ set biến môi trường (không đọc .env):
 *   $env:SUPABASE_URL="https://xxx.supabase.co"; $env:SUPABASE_SERVICE_ROLE_KEY="eyJ..."; node scripts/check-proxies.mjs
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

function usernamePreview(s, max = 36) {
  if (s == null || s === "") return "";
  if (s.length <= max) return s;
  return s.slice(0, max) + "…(" + s.length + " chars)";
}

function passwordMask(s) {
  if (s == null || s === "") return "";
  return "***(" + s.length + " chars)";
}

async function main() {
  loadDotEnv();
  const url = process.env.SUPABASE_URL?.replace(/\/$/, "");
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    console.error(
      "Thiếu SUPABASE_URL hoặc SUPABASE_SERVICE_ROLE_KEY (trong .env hoặc env)."
    );
    process.exit(1);
  }

  const endpoint = `${url}/rest/v1/proxies?select=id,label,http_host,http_port,socks_host,socks_port,username,password,is_active,last_rotated_at,leased_by,leased_at&order=id`;
  const res = await fetch(endpoint, {
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      Accept: "application/json",
    },
  });

  if (!res.ok) {
    const body = await res.text();
    console.error(`HTTP ${res.status}:`, body.slice(0, 500));
    process.exit(1);
  }

  const rows = await res.json();
  if (!Array.isArray(rows)) {
    console.error("Response không phải mảng:", rows);
    process.exit(1);
  }

  console.log(`Kết nối OK — ${rows.length} dòng trong public.proxies\n`);
  for (const r of rows) {
    const userPv = usernamePreview(r.username);
    console.log(
      JSON.stringify(
        {
          id: r.id,
          label: r.label,
          is_active: r.is_active,
          leased_by: r.leased_by ?? null,
          leased_at: r.leased_at ?? null,
          last_rotated_at: r.last_rotated_at,
          http: `${r.http_host}:${r.http_port}`,
          socks: `${r.socks_host}:${r.socks_port}`,
          username_preview: userPv,
          password: passwordMask(r.password),
          proxy_http_shape: `http://${userPv.includes("…") ? userPv.split("…")[0] + "…" : userPv}:***@${r.http_host}:${r.http_port}`,
        },
        null,
        2
      )
    );
    console.log("---");
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
