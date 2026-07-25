// Boot validation for `BridgeConfig.redirectAllowlist` (contracts §5 / §10.1).
// Kept out of `config.ts` so that file stays under the 250-line limit; the
// validator returns a message rather than throwing, so there is no import cycle
// with `AuthConfigError` — `createBridgeConfig` throws it.
//
// Why this exists: `assertAllowedRedirectUri` (redirect.ts) silently discards a
// `"*"` entry at request time. That fails closed, but it is SILENT in both
// directions — a deployer who configured allow-all learned nothing at boot, and
// `"*"` survived in manifests as apparently-live config whose inertness rested
// on one `return false` in the matcher rather than on the config being refused.
// These rules mirror what the matcher already refuses for the INCOMING
// redirect_uri, so the decision and the enforcement act on the same rules.

/** Schemes a redirect target may legitimately use. An allowlist, never a
 *  blocklist: `javascript:`/`data:`/`file:` and every other scheme are rejected
 *  because they are not reachable redirect targets for an OAuth client. */
const ALLOWED_REDIRECT_SCHEMES: ReadonlySet<string> = new Set(["https:", "http:"]);

/** Validate every entry, returning a boot-failure message or the frozen
 *  snapshot to publish. Entries are read from the array ONCE (into `entries`)
 *  and it is THAT copy which is both validated and returned — a getter-backed
 *  or later-mutated caller array cannot swap in an unvalidated value after the
 *  check (the read-once rule; same shape as `cimdConfigProblem`).
 *
 *  An empty list is valid: the built-in §10 defaults already cover the common
 *  case, so only *entries* can be invalid, never emptiness. */
export function redirectAllowlistProblem(
  value: unknown,
): { problem: string } | { value: readonly string[] } {
  if (!Array.isArray(value)) {
    return { problem: "redirectAllowlist must be an array of URL strings" };
  }
  // Single read of each index, before any validation.
  const entries: unknown[] = [...(value as unknown[])];
  for (const entry of entries) {
    const problem = entryProblem(entry);
    if (problem !== undefined) return { problem };
  }
  return { value: Object.freeze(entries as string[]) };
}

/** The per-entry rules. Returns a message naming the offending entry (so a
 *  deployer with several origins configured learns WHICH one is wrong without
 *  bisecting), or undefined when the entry is acceptable. */
function entryProblem(entry: unknown): string | undefined {
  if (typeof entry !== "string") {
    return `redirectAllowlist entries must be strings (got ${typeof entry})`;
  }
  const shown = JSON.stringify(entry);
  if (entry === "*") {
    return `redirectAllowlist entry ${shown} is not allowed: allow-all is refused at request time, so it grants nothing. Remove it, or list the exact origins you intend to allow (contracts §10.1).`;
  }
  // Checked on the RAW string BEFORE parsing: `new URL` percent-encodes a `*`
  // in a path, so a post-parse check cannot reliably see the one the deployer
  // wrote. Unanchored prefixes are refused by the matcher for the same reason
  // `"*"` is — they would widen an origin the deployer cannot audit.
  if (entry.includes("*")) {
    return `redirectAllowlist entry ${shown} is not allowed: wildcard/prefix entries are refused at request time (only exact URIs and origins match — contracts §10.1).`;
  }
  let url: URL;
  try {
    url = new URL(entry);
  } catch {
    return `redirectAllowlist entry ${shown} is not an absolute URL`;
  }
  if (!ALLOWED_REDIRECT_SCHEMES.has(url.protocol)) {
    return `redirectAllowlist entry ${shown} must use https:// or http:// (got "${url.protocol}")`;
  }
  if (url.username || url.password) {
    return `redirectAllowlist entry ${shown} must not contain userinfo`;
  }
  // `assertAllowedRedirectUri` strips the incoming hash before comparing, so a
  // fragment-bearing ENTRY can never be what makes a match succeed — it is
  // configuration that does not mean what it appears to mean.
  if (entry.includes("#")) {
    return `redirectAllowlist entry ${shown} must not contain a fragment (the fragment is stripped before matching, so it has no effect)`;
  }
  // The matcher compares a PATH-BEARING entry against the incoming URI by exact
  // string equality (`entry === normalized`), where `normalized` is `url.href` —
  // already canonicalized by WHATWG. A non-canonical entry (`HTTPS://…`,
  // `…:443/cb`, surrounding whitespace, a `/a/../cb` dot segment) therefore
  // matches NOTHING, and the deployer's configured callback fails at
  // authorization rather than at boot — the same silent-config failure this
  // module exists to end. Rejected, not silently rewritten: the entry should say
  // what it means, and the message shows the canonical form to paste back.
  //
  // Only path-bearing entries are affected. An origin-only entry has its own
  // matcher branch (compared as `scheme://host`, and for loopback via the raw
  // string), so `https://a.test` is canonical for our purposes even though
  // `new URL` would render it `https://a.test/`.
  const isOriginOnly = (url.pathname === "" || url.pathname === "/") && !url.search;
  if (!isOriginOnly && entry !== url.href) {
    return `redirectAllowlist entry ${shown} is not in canonical form and would match nothing (the matcher compares against the normalized URI). Use "${url.href}".`;
  }
  return undefined;
}
