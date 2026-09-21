import { randomBase64Url, sha256Base64Url } from "../../_shared/crypto.js";
import { getCookie, clearTxCookie, sessionCookie } from "../../_shared/cookies.js";
import { getProvider, fetchGithubIdentity } from "../../_shared/providers.js";
import { verifyGoogleIdToken } from "../../_shared/oidc.js";

const fail = (status = 400) =>
  new Response("Falha na autenticação.", {
    status,
    headers: { "Cache-Control": "no-store", "Set-Cookie": clearTxCookie() },
  });

export async function onRequestGet({ request, params, env }) {
  const provider = getProvider(params.provider);
  if (!provider) return new Response("Not found", { status: 404 });

  const url = new URL(request.url);
  if (url.searchParams.has("error")) return fail();
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) return fail();

  const txId = getCookie(request, "__Host-oauth-tx");
  if (!txId) return fail();

  // Busca E apaga em uma operação só: uso único garantido
  const now = Math.floor(Date.now() / 1000);
  const tx = await env.DB.prepare(
    `DELETE FROM oauth_transactions
     WHERE id_hash = ?1 AND expires_at > ?2 RETURNING *`
  ).bind(await sha256Base64Url(txId), now).first();

  if (!tx || tx.provider !== params.provider) return fail();
  if ((await sha256Base64Url(state)) !== tx.state_hash) return fail();

  try {
    // troca do código por tokens (servidor -> provedor)
    const res = await fetch(provider.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: `${env.PUBLIC_BASE_URL}/oauth/callback/${params.provider}`,
        client_id: provider.clientId(env),
        client_secret: provider.clientSecret(env),
        code_verifier: tx.code_verifier,
      }),
    });
    if (!res.ok) return fail(502);
    const tokens = await res.json();

    const identity =
      params.provider === "google"
        ? await verifyGoogleIdToken(tokens.id_token, {
            clientId: env.GOOGLE_CLIENT_ID,
            nonce: tx.nonce,
          })
        : await fetchGithubIdentity(tokens, env);

    // só chegamos aqui com identidade totalmente confirmada
    const sessionId = randomBase64Url();
    await env.DB.prepare(
      `INSERT INTO sessions
       (id_hash, issuer, subject, email, display_name, expires_at, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`
    ).bind(
      await sha256Base64Url(sessionId),
      identity.issuer, identity.subject,
      identity.email, identity.displayName,
      now + 28800, now
    ).run();

    const headers = new Headers({
      Location: `${env.PUBLIC_BASE_URL}/`,
      "Cache-Control": "no-store",
    });
    headers.append("Set-Cookie", clearTxCookie());
    headers.append("Set-Cookie", sessionCookie(sessionId));
    return new Response(null, { status: 302, headers });
  } catch {
    return fail(401); // nunca logue o erro com tokens/corpo
  }
}
