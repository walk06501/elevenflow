/**
 * Test từng URL trong WEBSHARE_LIST_URLS — in plan_id + số proxy / HTTP status.
 * Không in full URL (có token).
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

function label(url) {
  const m = url.match(/download\/([a-z0-9]{8})/i);
  const p = url.match(/plan_id=(\d+)/);
  return `token=${m ? m[1] + "…" : "?"} plan_id=${p ? p[1] : "?"}`;
}

async function main() {
  loadDotEnv();
  const raw = process.env.WEBSHARE_LIST_URLS ?? "";
  const urls = raw.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
  console.log(`Có ${urls.length} link trong WEBSHARE_LIST_URLS:\n`);
  for (let i = 0; i < urls.length; i++) {
    const url = urls[i];
    try {
      const res = await fetch(url, { cache: "no-store", signal: AbortSignal.timeout(15000) });
      const text = await res.text();
      if (!res.ok) {
        console.log(`[${i + 1}] DIE  ${label(url)}  HTTP ${res.status}  body=${text.slice(0, 80).replace(/\s+/g, " ")}`);
        continue;
      }
      const lines = text.split(/\r?\n/).filter((l) => l.trim() && l.includes(":"));
      console.log(`[${i + 1}] OK   ${label(url)}  proxies=${lines.length}`);
    } catch (e) {
      console.log(`[${i + 1}] DIE  ${label(url)}  error=${e.message}`);
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
