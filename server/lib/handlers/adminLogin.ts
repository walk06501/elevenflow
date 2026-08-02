import type { VercelRequest, VercelResponse } from "@vercel/node";
import { SignJWT } from "jose";
import { adminSigningKey } from "../adminAuth";

/** POST /api/admin/login */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "method not allowed" });
  }

  const key = adminSigningKey();
  if (!key) {
    return res.status(503).json({
      error: "admin_signing_not_configured",
      hint: "ELEVENFLOW_ADMIN_SECRET >= 32 chars required.",
    });
  }

  const expectedUser = (
    process.env.ELEVENFLOW_ADMIN_USERNAME ?? "admin"
  ).trim();
  const expectedPass = process.env.ELEVENFLOW_ADMIN_PASSWORD;
  if (!expectedPass) {
    return res.status(503).json({
      error: "admin_password_not_configured",
      hint: "Set ELEVENFLOW_ADMIN_PASSWORD on Vercel.",
    });
  }

  const body = (req.body ?? {}) as { username?: string; password?: string };
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const password = typeof body.password === "string" ? body.password : "";

  if (username !== expectedUser || password !== expectedPass) {
    return res.status(401).json({ error: "invalid_credentials" });
  }

  const token = await new SignJWT({ role: "admin" as const })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject("admin")
    .setIssuedAt()
    .setExpirationTime("8h")
    .sign(key);

  return res.status(200).json({ token });
}
