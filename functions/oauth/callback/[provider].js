import { randomBase64Url, sha256Base64Url } from "../../_shared/crypto.js";
import { getCookie, clearTxCookie, sessionCookie } from "../../_shared/cookies.js";
import { getProvider, fetchGithubIdentity } from "../../_shared/providers.js";
import { verifyGoogleIdToken } from "../../_shared/oidc.js";

const fail = (reason, status = 400) =>
  new Response("Falha na autenticacao. Motivo: " + reason, {
    status: status,
    headers: { "Cache-Control": "no-store", "Set-Cookie": clearTxCookie() },
  });

export async function onRequestGet({ request, params, env }) {
  const provider = getProvider(params.provider);
  if (!provider) return new Response("Not found", { status: 404 });

  const url = new URL(request.url);
  if (url.searchParams.has("error")) {
    return fail("FAIL-1 error=" + url.searchParams.get("error"));
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) {
    return fail("FAIL-2 code/state ausente");
  }

  const txId = getCookie(request, "__Host-oauth-tx");
  if (!txId) {
    return fail("FAIL-3 cookie ausente");
  }

  const now = Math.floor(Date.now() / 1000);
  const idHash = await sha256Base64Url(txId);

  const tx = await env.DB.prepare(
    "SELECT * FROM oauth_transactions WHERE id_hash = ?1 AND expires_at > ?2"
  ).bind(idHash, now).first();

  if (!tx) {
    return fail("FAIL-4 transacao nao encontrada no SELECT");
  }

  await env.DB.prepare(
    "DELETE FROM oauth_transactions WHERE id_hash = ?1"
  ).bind(idHash).run();

  if (tx.provider !== params.provider) {
    return fail("FAIL-5 provider errado: salvo=" + tx.provider + " esperado=" + params.provider);
  }

  const stateHash = await sha256Base64Url(state);
  if (stateHash !== tx.state_hash) {
    return fail("FAIL-6 state nao confere");
  }

  try {
    if (params.provider === "google") {
      const secret = env.GOOGLE_CLIENT_SECRET;
      const clientId = env.GOOGLE_CLIENT_ID;
      const secretExiste = secret ? "sim" : "NAO";
      const secretTamanho = secret ? secret.length : 0;
      const secretInicio = secret ? secret.slice(0, 6) : "-";
      const secretFim = secret ? secret.slice(-4) : "-";
      const clientIdExiste = clientId ? "sim" : "NAO";
      const clientIdTamanho = clientId ? clientId.length : 0;
      const
