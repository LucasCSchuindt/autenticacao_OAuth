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
  if (url.searchParams.has("error")) return fail("FAIL-1 error param presente: " + url.searchParams.get("error"));
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) return fail("FAIL-2 code ou state ausente");

  const txId = getCookie(request, "__Host-oauth-tx");
  if (!txId) return fail("FAIL-3 cookie __Host-oauth-tx ausente na requisicao");

  const now = Math.floor(Date.now() / 1000);
  const computedHash = await sha256Base64Url(txId);

  // DIAGNÓSTICO: olhar sem apagar, para ver o que existe de verdade
  const debugRow = await env.DB.prepare(
    `SELECT id_hash, provider, expires_at FROM oauth_transactions WHERE id_hash = ?1`
  ).bind(computedHash).first();

  const debugCount = await env.DB.prepare(
    `SELECT COUNT(*) as n FROM oauth_transactions`
  ).first();

  if (!debugRow) {
    return fail(
      "FAIL-4-DIAG: nenhuma linha com esse id_hash existe no banco. " +
      "total de linhas na tabela: " + debugCount.n +
      ". hash calculado (primeiros 10 chars): " + computedHash.slice(0, 10) +
      ". txId do cookie (primeiros 10 chars): " + txId.slice(0, 10)
    );
  }

  return fail(
    "FAIL-4-DIAG: linha ENCONTRADA. provider=" + debugRow.provider +
    " expires_at=" + debugRow.expires_at +
    " agora=" + now +
    " diferenca_segundos=" + (debugRow.expires_at - now)
  );
}
