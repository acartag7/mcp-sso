import { createLocalJWKSet, decodeJwt } from "jose";
import { verifyFlowToken } from "../../src/adapters/upstream-flow-internals.ts";

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
export const upstreamCookieValue = (cookie) => {
  const nameValue = cookie.split(";", 1)[0] ?? "";
  const equalsAt = nameValue.indexOf("=");
  if (equalsAt <= 0 || equalsAt === nameValue.length - 1) return undefined;
  return nameValue.slice(equalsAt + 1);
};
export const hasExpectedSignedFlowLifetime = async (
  token, secret, issuer, callbackPath, expectedSeconds,
) => {
  if (typeof token !== "string" || !Number.isInteger(expectedSeconds)
    || expectedSeconds <= 0 || expectedSeconds > 3_600) return false;
  try {
    const claims = await verifyFlowToken(token, secret, issuer, callbackPath);
    const issuedAt = decodeJwt(token).iat;
    return typeof issuedAt === "number" && Number.isFinite(issuedAt)
      && claims.exp - issuedAt === expectedSeconds;
  } catch {
    return false;
  }
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
