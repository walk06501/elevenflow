/**
 * Xoá SẠCH toàn bộ proxy source='webshare' trong DB (giữ nguyên proxyxoay),
 * rồi đồng bộ lại từ WEBSHARE_LIST_URLS hiện tại để có danh sách sạch, không
 * còn rác tồn đọng từ các plan/lần sync cũ.
 *
 * Chạy từ thư mục server:
 *   node scripts/reset-webshare-pool.mjs
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

  console.log("Đang xoá toàn bộ proxy source=webshare...");
  const delRes = await fetch(`${url}/rest/v1/proxies?source=eq.webshare`, {
    method: "DELETE",
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      Prefer: "return=representation",
    },
  });
  if (!delRes.ok) {
    console.error(`Xoá thất bại HTTP ${delRes.status}:`, (await delRes.text()).slice(0, 500));
    process.exit(1);
  }
  const deleted = await delRes.json();
  console.log(`Đã xoá ${deleted.length} proxy webshare.`);

  console.log("Đang đồng bộ lại từ WEBSHARE_LIST_URLS...");
  const secret = process.env.CRON_SECRET || process.env.APP_SECRET;
  const base = process.argv[2] || "https://server-nine-xi-24.vercel.app";
  const syncRes = await fetch(`${base}/api/cron/sync-proxies`, {
    method: "POST",
    headers: { "x-cron-secret": secret },
  });
  const syncText = await syncRes.text();
  console.log(syncRes.status, syncText);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
