export function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

const TX = "__Host-oauth-tx";
const SESSION = "__Host-session";

export const txCookie = (v) =>
  `${TX}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;
export const clearTxCookie = () =>
  `${TX}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

export const sessionCookie = (v) =>
  `${SESSION}=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`;
export const clearSessionCookie = () =>
  `${SESSION}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
