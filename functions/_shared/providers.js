export const PROVIDERS = {
  google: {
    authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    clientId: (env) => env.GOOGLE_CLIENT_ID,
    clientSecret: (env) => env.GOOGLE_CLIENT_SECRET,
    usesNonce: true,
  },
  github: {
    authUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    clientId: (env) => env.GITHUB_CLIENT_ID,
    clientSecret: (env) => env.GITHUB_CLIENT_SECRET,
    usesNonce: false,
  },
};

// hasOwn evita que "constructor" ou "__proto__" passem como provedor
export function getProvider(name) {
  return Object.hasOwn(PROVIDERS, name) ? PROVIDERS[name] : null;
}

const GH_HEADERS = {
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2026-03-10",
  "User-Agent": "oauth-pages-lab",
};

export async function fetchGithubIdentity(tokens, env) {
  if (!tokens.access_token || String(tokens.token_type).toLowerCase() !== "bearer") {
    throw new Error("token inválido");
  }

  // 1) quem é o usuário?
  const res = await fetch("https://api.github.com/user", {
    headers: { ...GH_HEADERS, Authorization: `Bearer ${tokens.access_token}` },
  });
  if (res.status !== 200) throw new Error("falha em /user");
  const user = await res.json();
  if (!Number.isInteger(user.id)) throw new Error("id inválido");

  // 2) revogar a autorização ANTES de criar sessão
  const cid = env.GITHUB_CLIENT_ID;
  const basic = btoa(`${cid}:${env.GITHUB_CLIENT_SECRET}`);
  const del = await fetch(`https://api.github.com/applications/${cid}/grant`, {
    method: "DELETE",
    headers: {
      ...GH_HEADERS,
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ access_token: tokens.access_token }),
  });
  if (del.status !== 204) throw new Error("falha ao revogar");

  return {
    issuer: "https://github.com",
    subject: String(user.id),          // id numérico: estável
    email: user.email ?? null,         // pode ser nulo, e tudo bem
    displayName: user.name ?? user.login ?? null, // só para exibir
  };
}
