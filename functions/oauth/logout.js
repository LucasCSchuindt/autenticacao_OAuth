import { getCookie, clearSessionCookie } from "../_shared/cookies.js";
import { sha256Base64Url } from "../_shared/crypto.js";

export async function onRequest({ request, env }) {
  const base = { "Cache-Control": "no-store" };

  if (request.method !== "POST")
    return new Response("Method not allowed", { status: 405, headers: { ...base, Allow: "POST" } });

  if (request.headers.get("Origin") !== env.PUBLIC_BASE_URL)
    return new Response("Forbidden", { status: 403, headers: base });

  const sid = getCookie(request, "__Host-session");
  if (sid) {
    await env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?1")
      .bind(await sha256Base64Url(sid)).run();
  }

  const headers = new Headers({ ...base, Location: `${env.PUBLIC_BASE_URL}/` });
  headers.append("Set-Cookie", clearSessionCookie());
  return new Response(null, { status: 303, headers });
}
