import { randomBase64Url, sha256Base64Url } from "../../_shared/crypto.js";
import { getCookie, clearTxCookie, sessionCookie } from "../../_shared/cookies.js";
import { getProvider, fetchGithubIdentity } from "../../_shared/providers.js";
import { verifyGoogleIdToken } from "../../_shared/oidc.js";

const GENERIC_MESSAGE = "Falha na autenticação. Volte à página inicial e tente novamente.";

// O motivo real vai só para o log do servidor.
// O usuário recebe apenas uma mensagem genérica.
const fail = (reason, status = 400, publicMessage = GENERIC_MESSAGE) => {
  console.error(`[oauth/callback] ${reason}`);
  return new Response(publicMessage, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "Set-Cookie": clearTxCookie(),
    },
  });
};

export async function onRequestGet({ request, params, env }) {
  const provider = getProvider(params.provider);
  if (!provider) return new Response("Not found", { status: 404 });

  const url = new URL(request.url);

  // O provedor devolveu erro (ex.: o usuário clicou em "Cancelar")
  const providerError = url.searchParams.get("error");
  if (providerError) {
    const message =
      providerError === "access_denied"
        ? "Login cancelado."
        : GENERIC_MESSAGE;
    return fail(`provedor retornou error=${providerError}`, 400, message);
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) {
    return fail("code ou state ausente");
  }

  const txId = getCookie(request, "__Host-oauth-tx");
  if (!txId) {
    return fail("cookie de transação ausente");
  }

  const now = Math.floor(Date.now() / 1000);
  const idHash = await sha256Base64Url(txId);

  const tx = await env.DB.prepare(
    "SELECT * FROM oauth_transactions WHERE id_hash = ?1 AND expires_at > ?2"
  ).bind(idHash, now).first();

  if (!tx) {
    return fail("transação não encontrada ou expirada");
  }

  // Uso único: a transação é apagada antes de qualquer outra verificação
  await env.DB.prepare(
    "DELETE FROM oauth_transactions WHERE id_hash = ?1"
  ).bind(idHash).run();

  if (tx.provider !== params.provider) {
    return fail(`provedor diferente do salvo (salvo=${tx.provider}, recebido=${params.provider})`);
  }

  const stateHash = await sha256Base64Url(state);
  if (stateHash !== tx.state_hash) {
    return fail("state não confere");
  }

  try {
    const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${params.provider}`;

    const res = await fetch(provider.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: provider.clientId(env),
        client_secret: provider.clientSecret(env),
        code_verifier: tx.code_verifier,
      }),
    });

    if (!res.ok) {
      const bodyText = await res.text();
      return fail(`troca de código por token falhou (status=${res.status}, corpo=${bodyText.slice(0, 200)})`, 502);
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
      "Location": `${env.PUBLIC_BASE_URL}/`,
      "Cache-Control": "no-store",
    });
    headers.append("Set-Cookie", clearTxCookie());
    headers.append("Set-Cookie", sessionCookie(sessionId));

    return new Response(null, { status: 302, headers });
  } catch (e) {
    return fail(`exceção durante o login: ${e.message}`, 401);
  }
}
