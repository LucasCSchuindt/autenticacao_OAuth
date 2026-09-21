import { getCookie } from "../_shared/cookies.js";
import { sha256Base64Url } from "../_shared/crypto.js";

export async function onRequestGet({ request, env }) {
  const headers = { "Cache-Control": "no-store" };
  const sid = getCookie(request, "__Host-session");
  if (!sid) return Response.json({ error: "unauthenticated" }, { status: 401, headers });

  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    `SELECT issuer, email, display_name FROM sessions
     WHERE id_hash = ?1 AND expires_at > ?2`
  ).bind(await sha256Base64Url(sid), now).first();

  if (!row) return Response.json({ error: "unauthenticated" }, { status: 401, headers });

  return Response.json(
    {
      provider: row.issuer === "https://github.com" ? "github" : "google",
      email: row.email,
      displayName: row.display_name,
    },
    { headers }
  );
}
