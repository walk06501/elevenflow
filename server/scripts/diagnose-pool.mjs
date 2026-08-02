/**
 * Chẩn đoán nhanh tình trạng pool proxies — đếm theo trạng thái để biết vì
 * sao "không có proxy nào rảnh" (banned_until, leased_by, is_active, hết hạn gói…).
 *
 * Chạy từ thư mục server (có file .env):
 *   node scripts/diagnose-pool.mjs
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

  const endpoint = `${url}/rest/v1/proxies?select=id,source,is_active,leased_by,leased_at,banned_until,ban_count,last_rotated_at,package_expires_at,api_key`;
  const res = await fetch(endpoint, {
    headers: { apikey: key, Authorization: `Bearer ${key}`, Accept: "application/json" },
  });
  if (!res.ok) {
    console.error(`HTTP ${res.status}:`, (await res.text()).slice(0, 500));
    process.exit(1);
  }
  const rows = await res.json();
  const now = Date.now();

  const stats = {
    total: rows.length,
    by_source: {},
    is_active_true: 0,
    is_active_false: 0,
    leased: 0,
    banned_now: 0,
    package_expired: 0,
    cooldown_60s: 0,
    leaseable_right_now: 0,
  };

  for (const r of rows) {
    stats.by_source[r.source || "?"] = (stats.by_source[r.source || "?"] || 0) + 1;
    if (r.is_active) stats.is_active_true++;
    else stats.is_active_false++;
    if (r.leased_by) stats.leased++;
    const bannedActive = r.banned_until && new Date(r.banned_until).getTime() > now;
    if (bannedActive) stats.banned_now++;
    const pkgExpired = r.package_expires_at && new Date(r.package_expires_at).getTime() <= now;
    if (pkgExpired) stats.package_expired++;
    const hasApiKey = r.api_key && String(r.api_key).trim() !== "";
    const lastRotated = r.last_rotated_at ? new Date(r.last_rotated_at).getTime() : 0;
    const inCooldown60 = hasApiKey && now - lastRotated < 60_000;
    if (inCooldown60) stats.cooldown_60s++;

    const leaseable =
      r.is_active &&
      !r.leased_by &&
      !bannedActive &&
      !pkgExpired &&
      !inCooldown60;
    if (leaseable) stats.leaseable_right_now++;
  }

  console.log("=== Tổng quan pool proxies ===");
  console.log(JSON.stringify(stats, null, 2));

  console.log("\n=== Mẫu 10 dòng banned_now=true (đang cooldown ban) ===");
  const bannedSample = rows
    .filter((r) => r.banned_until && new Date(r.banned_until).getTime() > now)
    .slice(0, 10)
    .map((r) => ({
      id: r.id,
      source: r.source,
      ban_count: r.ban_count,
      banned_until: r.banned_until,
      hours_left: ((new Date(r.banned_until).getTime() - now) / 3600000).toFixed(1),
    }));
  console.log(JSON.stringify(bannedSample, null, 2));

  console.log("\n=== Mẫu 10 dòng leaseable_right_now=true ===");
  const okSample = rows
    .filter((r) => {
      const bannedActive = r.banned_until && new Date(r.banned_until).getTime() > now;
      const pkgExpired = r.package_expires_at && new Date(r.package_expires_at).getTime() <= now;
      const hasApiKey = r.api_key && String(r.api_key).trim() !== "";
      const lastRotated = r.last_rotated_at ? new Date(r.last_rotated_at).getTime() : 0;
      const inCooldown60 = hasApiKey && now - lastRotated < 60_000;
      return r.is_active && !r.leased_by && !bannedActive && !pkgExpired && !inCooldown60;
    })
    .slice(0, 10)
    .map((r) => ({ id: r.id, source: r.source }));
  console.log(JSON.stringify(okSample, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
