// Confidential-client authentication helpers (contracts §17.2 / RFC 6749 §2.3.1,
// OAuth 2.1 §2.4.1). Framework-free: these parse the raw `Authorization` header
// value the bridge extracts, so the core grant use-case stays HTTP-agnostic.
//
// `client_secret_basic` (RFC 6749 §2.3.1): base64-decode the payload, split on
// the FIRST colon, then percent-decode each side (RFC 6749 Appendix B). Our
// client ids (`mcc_<base64url>`) and secrets (`mcs_<base64url>`) contain only
// unreserved chars, so encoding is a no-op for them — but we decode anyway so a
// spec-literal client that DID percent-encode round-trips correctly. `basic`
// here is STANDARD base64 (RFC 7617); base64url in a Basic header is rejected as
// non-compliant (treated as "no Basic credentials").

/**
 * Parse an `Authorization: Basic <b64>` value into client credentials.
 *
 * Returns `{ clientId, clientSecret }` on a well-formed Basic header, or `null`
 * when the header is absent, not the Basic scheme, or malformed (non-base64
 * payload, no colon, or a bad percent-escape). `null` is deliberately NOT an
 * oracle: the grant maps it to `invalid_client`, and the bridge decides the
 * `WWW-Authenticate` challenge from {@link isBasicAttempt}, which flags a Basic
 * SCHEME regardless of whether parsing succeeded (a malformed Basic still earns
 * the Basic challenge). */
export function parseBasicAuth(headerValue: string | undefined): { clientId: string; clientSecret: string } | null {
  if (typeof headerValue !== "string") return null;
  const match = /^basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(headerValue.trim());
  if (!match) return null; // absent, Bearer, or a non-standard base64 alphabet
  const decoded = Buffer.from(match[1]!, "base64").toString("utf8");
  const colon = decoded.indexOf(":"); // RFC 6749 §2.3.1: credentials are id:secret
  if (colon === -1) return null;
  const clientId = formUrlDecode(decoded.slice(0, colon));
  const clientSecret = formUrlDecode(decoded.slice(colon + 1));
  if (clientId === null || clientSecret === null) return null;
  return { clientId, clientSecret };
}

/**
 * True when the request carried an `Authorization: Basic` scheme — regardless of
 * whether {@link parseBasicAuth} could decode it. The grant sends
 * `WWW-Authenticate: Basic` on a failed `client_credentials` auth ONLY when Basic
 * was attempted (contracts §17.2: "WWW-Authenticate: Basic when Basic was
 * attempted"); a `client_secret_post` failure does not earn it. */
export function isBasicAttempt(headerValue: string | undefined): boolean {
  return typeof headerValue === "string" && /^basic\s+\S/i.test(headerValue.trim());
}

/** Reverse of RFC 6749 Appendix B (`application/x-www-form-urlencoded`): `+` →
 *  space, then percent-decode. Returns `null` on a malformed percent-sequence so
 *  the caller fails closed (invalid_client) instead of throwing. */
function formUrlDecode(value: string): string | null {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return null;
  }
}
