import { randomBase64Url, sha256Base64Url } from "../../_shared/crypto.js";
import { txCookie } from "../../_shared/cookies.js";
import { getProvider } from "../../_shared/providers.js";

export async function onRequestGet({ params, env }) {
  const provider = getProvider(params.provider);
  if (!provider) return new Response("Not found", { status: 404 });

  const txId = randomBase64Url();
  const state = randomBase64Url();
  const codeVerifier = randomBase64Url();
  const nonce = provider.usesNonce ? randomBase64Url() : null;
  const codeChallenge = await sha256Base64Url(codeVerifier);
  const expiresAt = Math.floor(Date.now() / 1000) + 600;

  await env.DB.prepare(
    `INSERT INTO oauth_transactions
     (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
  ).bind(
    await sha256Base64Url(txId),
    params.provider,
    await sha256Base64Url(state),
    nonce,
    codeVerifier,
    expiresAt
  ).run();

  const url = new URL(provider.authUrl);
  url.searchParams.set("client_id", provider.clientId(env));
  url.searchParams.set("redirect_uri", `${env.PUBLIC_BASE_URL}/oauth/callback/${params.provider}`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (params.provider === "google") {
    url.searchParams.set("scope", "openid email profile");
    url.searchParams.set("nonce", nonce);
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: url.toString(),
      "Set-Cookie": txCookie(txId),
      "Cache-Control": "no-store",
    },
  });
}
