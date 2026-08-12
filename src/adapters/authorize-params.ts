// Shared pure authorize-parameter occurrence rules. Every framework-free
// authorize entry point must reject multiplicity before selecting a value.

export const OAUTH_PARAM_KEYS = [
  "response_type", "client_id", "redirect_uri", "code_challenge",
  "code_challenge_method", "resource", "scope", "state",
] as const;

/** RFC 6749 §3.1 duplicate-param check: any key present more than once (array
 *  length > 1 in a normalized query/form record) is ambiguous. */
export function findDuplicatedKeys(input: unknown, keys: readonly string[]): string[] {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return [];
  const values = input as Record<string, unknown>;
  const duplicated: string[] = [];
  for (const key of keys) {
    const value = values[key];
    if (Array.isArray(value) && value.length > 1) duplicated.push(key);
  }
  return duplicated;
}
