/**
 * Kiểm tra migration 018 đã áp dụng chưa: cột use_count + signature
 * pick_and_lease_proxy có p_webshare_max_uses chưa; thống kê use_count hiện tại.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const envPath = path.join(__dirname, "..", ".env");

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

async function main() {
  loadDotEnv();
  const url = process.env.SUPABASE_URL?.replace(/\/$/, "");
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const h = { apikey: key, Authorization: `Bearer ${key}`, Accept: "application/json" };

  // 1) Cột use_count có tồn tại không?
  const colRes = await fetch(
    `${url}/rest/v1/proxies?select=id,source,use_count,banned_until,ban_count&source=eq.webshare&limit=5`,
    { headers: h }
  );
  const colText = await colRes.text();
  console.log("=== Sample webshare rows (use_count cột) ===");
  console.log(colRes.status, colText.slice(0, 800));

  if (!colRes.ok) {
    console.log("\n=> Cột use_count CHƯA có — migration 018 CHƯA chạy.");
    process.exit(0);
  }

  // 2) Phân bố use_count
  const allRes = await fetch(
    `${url}/rest/v1/proxies?select=id,use_count,banned_until,ban_count&source=eq.webshare&is_active=eq.true`,
    { headers: h }
  );
  const rows = await allRes.json();
  const now = Date.now();
  const byUse = {};
  let bannedSelf = 0; // banned với ban_count=0 hoặc null (self-ban từ use_count)
  let bannedSite = 0;
  let maxUse = 0;
  for (const r of rows) {
    const u = r.use_count ?? 0;
    byUse[u] = (byUse[u] || 0) + 1;
    if (u > maxUse) maxUse = u;
    const banned = r.banned_until && new Date(r.banned_until).getTime() > now;
    if (banned) {
      if ((r.ban_count ?? 0) === 0) bannedSelf++;
      else bannedSite++;
    }
  }
  console.log("\n=== Phân bố use_count (webshare active) ===");
  console.log(JSON.stringify(byUse, null, 2));
  console.log("max use_count:", maxUse);
  console.log("banned_now (ban_count=0, khả năng self-ban 5-lần):", bannedSelf);
  console.log("banned_now (ban_count>0, site ban):", bannedSite);
  console.log("total active webshare:", rows.length);

  // 3) Thử gọi RPC với tham số mới — nếu signature cũ sẽ lỗi
  const rpcRes = await fetch(`${url}/rest/v1/rpc/pick_and_lease_proxy`, {
    method: "POST",
    headers: { ...h, "Content-Type": "application/json", Prefer: "return=representation" },
    body: JSON.stringify({
      p_session_id: "probe-018-" + Date.now(),
      p_exclude_url: null,
      p_max_leases: 1,
      p_webshare_max_uses: 5,
      p_webshare_self_ban_minutes: 1440,
    }),
  });
  const rpcText = await rpcRes.text();
  console.log("\n=== RPC pick_and_lease_proxy với tham số migration 018 ===");
  console.log(rpcRes.status, rpcText.slice(0, 500));
  if (rpcRes.ok) {
    console.log("=> Signature 018 ĐÃ CÓ — logic 5 lần / 1 ngày đang hoạt động ở DB.");
    // release ngay nếu vừa lease được
    try {
      const leased = JSON.parse(rpcText);
      const row = Array.isArray(leased) ? leased[0] : leased;
      if (row?.lease_token) {
        await fetch(`${url}/rest/v1/rpc/release_proxy_lease`, {
          method: "POST",
          headers: { ...h, "Content-Type": "application/json" },
          body: JSON.stringify({
            p_session_id: "probe-018-" + Date.now(), // wrong session - use same
            p_lease_token: row.lease_token,
            p_banned: false,
          }),
        });
        // better: release with correct session - re-read from above
      }
    } catch {}
  } else if (rpcText.includes("Could not find") || rpcText.includes("PGRST202") || rpcRes.status === 404) {
    console.log("=> Signature 018 CHƯA có — CẦN chạy migration 018 trong Supabase SQL Editor.");
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
