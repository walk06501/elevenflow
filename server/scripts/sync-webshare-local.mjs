/**
 * Đồng bộ TOÀN BỘ WEBSHARE_LIST_URLS từ .env local thẳng vào Supabase
 * (không qua Vercel) — dùng khi env production chưa kịp cập nhật.
 *
 * Chạy từ thư mục server:
 *   node scripts/sync-webshare-local.mjs
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(__dirname, "..");
const envPath = path.join(serverRoot, ".env");

function loadDotEnv() {
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const eq = t.indexOf("=");
    if (eq <= 0) continue;
    const key = t.slice(0, eq).trim();
    let val = t.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
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
    const port = parseInt(line.slice(i1 + 1, i2).trim(), 10);
    const username = line.slice(i2 + 1, i3).trim();
    const password = line.slice(i3 + 1).trim();
    if (!host || !Number.isFinite(port) || port <= 0 || !username || !password) continue;
    out.push({ host, port, username, password, label: `webshare-${host}-${port}` });
  }
  return out;
}

function planLabel(url) {
  const p = url.match(/plan_id=(\d+)/);
  return p ? p[1] : "?";
}

async function main() {
  loadDotEnv();
  const sbUrl = process.env.SUPABASE_URL?.replace(/\/$/, "");
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!sbUrl || !key) {
    console.error("Thiếu SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY.");
    process.exit(1);
  }

  const urls = (process.env.WEBSHARE_LIST_URLS ?? "")
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (urls.length === 0) {
    console.error("WEBSHARE_LIST_URLS trống.");
    process.exit(1);
  }

  const merged = new Map();
  for (let i = 0; i < urls.length; i++) {
    const url = urls[i];
    try {
      const res = await fetch(url, { cache: "no-store", signal: AbortSignal.timeout(20000) });
      const text = await res.text();
      if (!res.ok) {
        console.log(`[${i + 1}] DIE plan_id=${planLabel(url)} HTTP ${res.status}`);
        continue;
      }
      const entries = parseWebshareList(text);
      console.log(`[${i + 1}] OK  plan_id=${planLabel(url)} proxies=${entries.length}`);
      for (const e of entries) merged.set(`${e.host}:${e.port}:${e.username}`, e);
    } catch (e) {
      console.log(`[${i + 1}] DIE plan_id=${planLabel(url)} ${e.message}`);
    }
  }

  const rows = Array.from(merged.values());
  console.log(`\nTổng unique: ${rows.length}. Đang upsert...`);

  const headers = {
    apikey: key,
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/json",
    Prefer: "return=representation",
  };

  let upserted = 0;
  const CHUNK = 200;
  for (let i = 0; i < rows.length; i += CHUNK) {
    const chunk = rows.slice(i, i + CHUNK);
    const res = await fetch(`${sbUrl}/rest/v1/rpc/upsert_webshare_proxies`, {
      method: "POST",
      headers,
      body: JSON.stringify({ p_rows: chunk }),
    });
    if (!res.ok) {
      console.error(`upsert fail HTTP ${res.status}:`, (await res.text()).slice(0, 400));
      process.exit(1);
    }
    const data = await res.json();
    upserted += typeof data === "number" ? data : chunk.length;
  }
  console.log(`Upserted: ${upserted}`);

  // Deactivate stale
  const listRes = await fetch(
    `${sbUrl}/rest/v1/proxies?select=id,http_host,http_port,username&source=eq.webshare&is_active=eq.true`,
    { headers: { apikey: key, Authorization: `Bearer ${key}` } }
  );
  const existing = await listRes.json();
  const staleIds = (existing || [])
    .filter((r) => !merged.has(`${r.http_host}:${r.http_port}:${r.username}`))
    .map((r) => r.id);
  if (staleIds.length > 0) {
    for (let i = 0; i < staleIds.length; i += 100) {
      const chunk = staleIds.slice(i, i + 100);
      const ids = chunk.join(",");
      await fetch(`${sbUrl}/rest/v1/proxies?id=in.(${ids})`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ is_active: false }),
      });
    }
  }
  console.log(`Deactivated stale: ${staleIds.length}`);
  console.log("Done.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
