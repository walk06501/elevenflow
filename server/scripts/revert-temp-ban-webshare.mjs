/**
 * Gỡ lệnh ban tạm 7 ngày vừa đặt bởi temp-ban-webshare.mjs — chỉ reset đúng
 * các dòng có banned_until KHỚP giá trị bulk đã set (tránh đụng vào các dòng
 * đang bị ban thật do site chặn, có banned_until khác thời điểm).
 *
 * Chạy từ thư mục server:
 *   node scripts/revert-temp-ban-webshare.mjs "<banned_until_iso_string>"
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
  const bannedUntilExact = process.argv[2];
  if (!bannedUntilExact) {
    console.error("Thiếu tham số banned_until (ISO string) để chỉ revert đúng bulk update.");
    process.exit(1);
  }

  const endpoint =
    `${url}/rest/v1/proxies?source=eq.webshare&banned_until=eq.${encodeURIComponent(bannedUntilExact)}`;
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
    console.error(`HTTP ${res.status}:`, (await res.text()).slice(0, 500));
    process.exit(1);
  }
  const rows = await res.json();
  console.log(`Đã gỡ ban tạm cho ${rows.length} proxy webshare.`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
