/**
 * Khôi phục các proxy webshare bị is_active=false OAN do migration 016 cũ
 * (tự động retire sau 3 lần ban) TRƯỚC KHI migration 017 sửa lại logic
 * (không còn tự loại khỏi pool nữa). Chỉ khôi phục dòng có ban_count=3 VÀ
 * last_seen_at gần đây (còn tồn tại trong list Webshare hiện tại, không phải
 * bị Webshare loại bỏ thật) — tránh khôi phục nhầm proxy đã chết hẳn.
 *
 * Chạy từ thư mục server:
 *   node scripts/reactivate-retired-webshare.mjs
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

  const cutoff = new Date(Date.now() - 48 * 3600_000).toISOString();
  const endpoint =
    `${url}/rest/v1/proxies?is_active=eq.false&ban_count=eq.3&last_seen_at=gte.${encodeURIComponent(cutoff)}`;

  const res = await fetch(endpoint, {
    method: "PATCH",
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
    },
    body: JSON.stringify({ is_active: true }),
  });
  if (!res.ok) {
    console.error(`HTTP ${res.status}:`, (await res.text()).slice(0, 500));
    process.exit(1);
  }
  const rows = await res.json();
  console.log(`Đã khôi phục is_active=true cho ${rows.length} proxy (ban_count=3, last_seen_at >= 48h gần đây).`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
