import type { VercelRequest, VercelResponse } from "@vercel/node";
import { commercialAuthEnabled } from "../commercialGate";

/** GET /api/config */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "GET") {
    return res.status(405).json({ error: "method not allowed" });
  }
  return res.status(200).json({
    commercialAuth: commercialAuthEnabled(),
  });
}
