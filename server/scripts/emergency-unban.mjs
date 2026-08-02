/**
 * Giải cứu khẩn cấp: pool cạn kiệt vì cooldown ban 1 ngày áp cho MỌI lần bị
 * ban (kể cả lần đầu) khiến gần hết pool active bị khoá cùng lúc. Gỡ ngay
 * banned_until cho các dòng CHƯA tới ngưỡng tự nghỉ hưu (ban_count < 3) để
 * pool hoạt động lại trong lúc chờ migration 017 (cooldown luỹ tiến) áp dụng
 * cho các lần ban SAU này.
 *
 * Chạy từ thư mục server (có file .env):
 *   node scripts/emergency-unban.mjs
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

  const nowIso = new Date().toISOString();
  // Chỉ gỡ cho dòng chưa chạm ngưỡng nghỉ hưu (ban_count < 3) — dòng đã >=3
  // lẽ ra đã bị is_active=false rồi, giữ nguyên không đụng vào.
  const endpoint = `${url}/rest/v1/proxies?banned_until=gt.${encodeURIComponent(nowIso)}&ban_count=lt.3`;
  const res = await fetch(endpoint, {
    method: "PATCH",
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
    },
    body: JSON.stringify({ banned_until: null }),
  });
  if (!res.ok) {
    console.error(`HTTP ${res.status}:`, (await res.text()).slice(0, 800));
    process.exit(1);
  }
  const rows = await res.json();
  console.log(`Đã gỡ banned_until cho ${rows.length} proxy (ban_count < 3) — pool hoạt động lại ngay.`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
