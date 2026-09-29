import { randomBase64Url, sha256Base64Url } from "../../_shared/crypto.js";
import { getCookie, clearTxCookie, sessionCookie } from "../../_shared/cookies.js";
import { getProvider, fetchGithubIdentity } from "../../_shared/providers.js";
import { verifyGoogleIdToken } from "../../_shared/oidc.js";

const fail = (reason, status = 400) =>
  new Response("Falha na autenticação. Motivo: " + reason, {
    status,
    headers: { "Cache-Control": "no-store", "Set-Cookie": clearTxCookie() },
  });

export async function onRequestGet({ request, params, env }) {
  const provider = getProvider(params.provider);
  if (!provider) return new Response("Not found", { status: 404 });

  const url = new URL(request.url);
  if (url.searchParams.has("error")) return fail("FAIL-1 error=" + url.searchParams.get("error"));
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) return fail("FAIL-2 code/state ausente");

  const txId = getCookie(request, "__Host-oauth-tx");
  if (!txId) return fail("FAIL-3 cookie ausente");

  const now = Math.floor(Date.now() / 1000);
  const idHash = await sha256Base64Url(txId);

  const tx = await env.DB.prepare(
    `SELECT * FROM oauth_transactions WHERE id_hash = ?1 AND expires_at > ?2`
  ).bind(idHash, now).first();

  if (!tx) return fail("FAIL-4 transacao nao encontrada no SELECT");

  await env.DB.prepare(
    `DELETE FROM oauth_transactions WHERE id_hash = ?1`
  ).bind(idHash).run();

  if (tx.provider !== params.provider) return fail("FAIL-5 provider errado: salvo=" + tx.provider + " esperado=" + params.provider);
  if ((await sha256Base64Url(state)) !== tx.state_hash) return fail("FAIL-6 state nao confere");

  try {
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
    if (!res.ok) {
      const bodyText = await res.text();
      return fail("FAIL-7
