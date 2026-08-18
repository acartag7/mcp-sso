import { createLocalJWKSet } from "jose";

export const fetchJson = async (url) => {
  const response = await fetch(url, {
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
    headers: { accept: "application/json" },
  });
  return { status: response.status, body: await response.json() };
};
export const matchesUpstreamCookieProfile = (cookie, issuer, expectedMaxAge) => {
  if (!Number.isInteger(expectedMaxAge)
    || expectedMaxAge <= 0 || expectedMaxAge > 3_600) return false;
  let url;
  try {
    url = new URL(issuer);
  } catch {
    return false;
  }
  const secure = url.protocol === "https:";
  const loopback = url.protocol === "http:"
    && new Set(["localhost", "127.0.0.1", "[::1]"]).has(url.hostname);
  if (!secure && !loopback) return false;
  const name = secure ? "__Host-mcp-sso-upstream" : "mcp-sso-upstream";
  const parts = cookie.split("; ");
  const expectedAttributes = secure
    ? ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"]
    : ["Path=/", "HttpOnly", "SameSite=Lax"];
  return parts[0]?.startsWith(`${name}=`) === true
    && parts[0].length > name.length + 1
    && expectedAttributes.every((attribute) => parts.includes(attribute))
    && parts.filter((part) => part === `Max-Age=${expectedMaxAge}`).length === 1
    && parts.length === expectedAttributes.length + 2;
};
export const countUsableRs256Keys = async (document) => {
  if (document === null || typeof document !== "object"
    || !Array.isArray(document.keys)) return 0;
  let usable = 0;
  for (const key of document.keys) {
    if (key === null || typeof key !== "object"
      || typeof key.kid !== "string" || key.kid.length === 0) continue;
    try {
      // createRemoteJWKSet uses this same local resolver after its network read.
      const resolveKey = createLocalJWKSet({ keys: [key] });
      await resolveKey({
        alg: "RS256",
        kid: key.kid,
      });
      usable++;
    } catch {
      // The shipped remote-JWKS verifier rejects this entry for RS256 verification.
    }
  }
  return usable;
};
