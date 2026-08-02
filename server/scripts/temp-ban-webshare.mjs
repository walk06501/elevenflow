/**
 * Tạm thời ban TOÀN BỘ proxy nguồn webshare trong N ngày (mặc định 7) để test
 * riêng nguồn proxyxoay — không đụng is_active, chỉ set banned_until nên tự
 * động hết hạn, không cần nhớ bật lại tay.
 *
 * Chạy từ thư mục server:
 *   node scripts/temp-ban-webshare.mjs [days]
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
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = val;
  }
}

async function main() {
  loadDotEnv();
  const url = process.env.SUPABASE_URL?.replace(/\/$/, "");
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    console.error("Thiếu SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY.");
    process.exit(1);
  }

  const days = Number(process.argv[2] ?? "7") || 7;
  const bannedUntil = new Date(Date.now() + days * 86400_000).toISOString();

  const endpoint = `${url}/rest/v1/proxies?source=eq.webshare&is_active=eq.true`;
  const res = await fetch(endpoint, {
    method: "PATCH",
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
    },
    body: JSON.stringify({ banned_until: bannedUntil }),
  });
  if (!res.ok) {
    console.error(`HTTP ${res.status}:`, (await res.text()).slice(0, 500));
    process.exit(1);
  }
  const rows = await res.json();
  console.log(`Đã ban tạm ${rows.length} proxy webshare đến ${bannedUntil} (${days} ngày).`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
