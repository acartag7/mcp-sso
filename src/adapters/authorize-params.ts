// Shared pure authorize-parameter occurrence rules. Every framework-free
// authorize entry point must reject multiplicity before selecting a value.

export const OAUTH_PARAM_KEYS = [
  "response_type", "client_id", "redirect_uri", "code_challenge",
  "code_challenge_method", "resource", "scope", "state",
] as const;

/** Authorize parameters that RFC 6749 requires to occur at most once. RFC 8707
 * permits `resource` to repeat, so unsupported resource sets use invalid_target. */
export const OAUTH_SINGLETON_PARAM_KEYS = OAUTH_PARAM_KEYS.filter((key) => key !== "resource");

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
