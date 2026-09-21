import { fromBase64Url } from "./crypto.js";

const ISSUER = "https://accounts.google.com";
const td = new TextDecoder();
const parse = (part) => JSON.parse(td.decode(fromBase64Url(part)));

export async function verifyGoogleIdToken(idToken, { clientId, nonce }) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("formato");
  const [h, p, s] = parts;

  const header = parse(h);
  if (header.alg !== "RS256" || !header.kid) throw new Error("alg/kid");

  // descoberta OIDC -> jwks_uri
  const disc = await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json();
  if (disc.issuer !== ISSUER) throw new Error("emissor");
  const jwks = await (await fetch(disc.jwks_uri)).json();

  const jwk = jwks.keys.find((k) => k.kid === header.kid && k.kty === "RSA");
  if (!jwk) throw new Error("chave não encontrada");

  const key = await crypto.subtle.importKey(
    "jwk", jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false, ["verify"]
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key,
    fromBase64Url(s),
    new TextEncoder().encode(`${h}.${p}`)   // o que foi assinado
  );
  if (!valid) throw new Error("assinatura");

  // Só agora confiamos nos claims
  const c = parse(p);
  const now = Math.floor(Date.now() / 1000);
  const skew = 60;

  if (c.iss !== ISSUER && c.iss !== "accounts.google.com") throw new Error("iss");
  if (c.aud !== clientId) throw new Error("aud");
  if (typeof c.exp !== "number" || c.exp <= now - skew) throw new Error("exp");
  if (typeof c.iat !== "number" || c.iat > now + skew) throw new Error("iat");
  if (!nonce || c.nonce !== nonce) throw new Error("nonce");
  if (!c.sub) throw new Error("sub");

  return {
    issuer: ISSUER,
    subject: c.sub,
    email: c.email ?? null,
    displayName: c.name ?? null,
  };
}
