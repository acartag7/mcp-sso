// Shared pure authorize-parameter occurrence rules. Every framework-free
// authorize entry point must reject multiplicity before selecting a value.

export const OAUTH_PARAM_KEYS = [
  "response_type", "client_id", "redirect_uri", "code_challenge",
  "code_challenge_method", "resource", "scope", "state",
] as const;

/** Authorize parameters that RFC 6749 requires to occur at most once. RFC 8707
 * permits `resource` to repeat, so unsupported resource sets use invalid_target. */
export const OAUTH_SINGLETON_PARAM_KEYS = OAUTH_PARAM_KEYS.filter((key) => key !== "resource");

/** Recognized OAuth form fields that must occur at most once on the wire. */
export const APPROVE_SINGLETON_PARAM_KEYS = ["consent_token", "approved"] as const;
export const REGISTER_SINGLETON_PARAM_KEYS = [
  "redirect_uris", "application_type", "token_endpoint_auth_method", "grant_types",
] as const;
export const TOKEN_SINGLETON_PARAM_KEYS = [
  "grant_type", "code", "redirect_uri", "client_id", "code_verifier",
  "refresh_token", "client_secret", "scope", "resource",
] as const;
export const REVOKE_SINGLETON_PARAM_KEYS = ["token", "token_type_hint"] as const;

/** Pairing POST body singletons: authorize params plus the pairing session fields. */
export const PAIRING_BODY_SINGLETON_PARAM_KEYS = [
  ...OAUTH_SINGLETON_PARAM_KEYS, "pairing_code", "pairing_nonce",
] as const;

/** RFC 6749 §3.1 duplicate-param check after valueless occurrences are omitted. */
export function findDuplicatedKeys(input: unknown, keys: readonly string[]): string[] {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return [];
  const values = input as Record<string, unknown>;
  const duplicated: string[] = [];
  for (const key of keys) {
    const value = values[key];
    if (Array.isArray(value) && value.filter((entry) => entry !== "").length > 1) duplicated.push(key);
  }
  return duplicated;
}

/** Strict occurrence count for callback parameters, including empty values. */
export function findRepeatedKeys(input: unknown, keys: readonly string[]): string[] {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return [];
  const values = input as Record<string, unknown>;
  return keys.filter((key) => Array.isArray(values[key]) && values[key].length > 1);
}

export function hasDuplicatedAuthorizeParams(query: unknown): boolean {
  return findDuplicatedKeys(query, OAUTH_SINGLETON_PARAM_KEYS).length > 0;
}

/** Reconstruct raw query occurrences independently of framework parser policy. */
export function queryOccurrencesFromUrl(rawUrl: string): Record<string, string | string[]> {
  return collectOccurrences(new URL(rawUrl, "http://localhost").searchParams);
}

/** Reconstruct URL-encoded form occurrences (same rules as the query snapshot). */
export function formOccurrencesFromUrlEncoded(raw: string): Record<string, string | string[]> {
  return collectOccurrences(new URLSearchParams(raw));
}

function collectOccurrences(params: URLSearchParams): Record<string, string | string[]> {
  const out = Object.create(null) as Record<string, string | string[]>;
  for (const [key, value] of params) {
    const existing = out[key];
    if (existing === undefined) out[key] = value;
    else if (Array.isArray(existing)) existing.push(value);
    else out[key] = [existing, value];
  }
  return out;
}
