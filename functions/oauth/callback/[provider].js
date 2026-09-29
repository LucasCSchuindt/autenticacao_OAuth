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
    const redirectUri = env.PUBLIC_BASE_URL + "/oauth/callback/" + params.provider;
    if (params.provider === "google") {
      const secret = env.GOOGLE_CLIENT_SECRET;
      const clientId = env.GOOGLE_CLIENT_ID;
      return fail(
        "DIAG-SECRET " +
        "secretExiste=" + (secret ? "sim" : "NAO") + " " +
        "secretTamanho=" + (secret ? secret.length : 0) + " " +
        "secretInicio=" + (secret ? secret.slice(0, 6) : "-") + " " +
        "secretFim=" + (secret ? secret.slice(-4) : "-") + " " +
        "clientIdExiste=" + (clientId ? "sim" : "NAO") + " " +
        "clientIdTamanho=" + (clientId ? clientId.length : 0) + " " +
        "clientIdFim=" + (clientId ? clientId.slice(-10) : "-")
      );
    }

    const res = await fetch(provider.tokenUrl, {
    const res = await fetch(provider.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirectUri,
        client_id: provider.clientId(env),
        client_secret: provider.clientSecret(env),
        code_verifier: tx.code_verifier,
      }),
    });

    if (!res.ok) {
      const bodyText = await res.text();
      return fail("FAIL-7 token exchange status=" + res.status + " corpo=" + bodyText.slice(0, 400), 502);
    }

    const tokens = await res.json();

    let identity;
    if (params.provider === "google") {
      identity = await verifyGoogleIdToken(tokens.id_token, {
        clientId: env.GOOGLE_CLIENT_ID,
        nonce: tx.nonce,
      });
    } else {
      identity = await fetchGithubIdentity(tokens, env);
    }

    const sessionId = randomBase64Url();
    const sessionHash = await sha256Base64Url(sessionId);

    await env.DB.prepare(
      "INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    ).bind(
      sessionHash,
      identity.issuer,
      identity.subject,
      identity.email,
      identity.displayName,
      now + 28800,
      now
    ).run();

    const headers = new Headers({
      "Location": env.PUBLIC_BASE_URL + "/",
      "Cache-Control": "no-store",
    });
    headers.append("Set-Cookie", clearTxCookie());
    headers.append("Set-Cookie", sessionCookie(sessionId));

    return new Response(null, { status: 302, headers: headers });
  } catch (e) {
    return fail("FAIL-8 excecao=" + e.message, 401);
  }
}
