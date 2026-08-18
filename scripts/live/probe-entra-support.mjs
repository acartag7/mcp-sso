import { createLocalJWKSet } from "jose";

export const fetchJson = async (url) => {
  const response = await fetch(url, {
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
    headers: { accept: "application/json" },
  });
  return { status: response.status, body: await response.json() };
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
