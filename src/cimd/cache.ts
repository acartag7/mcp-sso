// CIMD validated-success cache (§17.1.4 + §17.1.6 decision 4). Keyed by the RAW
// presented client_id string (raw-string identity rule — `:443` and an
// uppercase host are DISTINCT entries), bounded to a finite entry ceiling with
// deterministic LRU eviction, in-memory per resolver instance. Only validated
// successes with a cacheable response are stored; error/invalid results never
// are. All arithmetic is pure — timestamps come from the caller's ClockPort.

import type { CimdRegistration } from "./registration.ts";
import type { CimdCacheView } from "./transport.ts";

const MIN_CACHEABLE_MAX_AGE = 60;
const DEFAULT_MAX_ENTRIES = 256;
const UNSIGNED_DECIMAL = /^[0-9]+$/;
/** RFC 9110 token — the only shape a Cache-Control directive name may take.
 *  Anchored, bounded character class, no backtracking (ReDoS-safe). */
const DIRECTIVE_NAME = /^[!#$%&'*+.^_`|~0-9a-z-]+$/;
/** Split a Cache-Control field into directives on commas that are OUTSIDE a
 *  quoted-string. A naive `split(",")` shreds a legal `foo="a,b"` into malformed
 *  fragments, so a response carrying an unknown-but-well-formed extension would
 *  become non-cacheable and re-fetch on every authorization. */
function splitDirectives(header: string): string[] {
  const out: string[] = [];
  let start = 0, quoted = false;
  for (let i = 0; i < header.length; i += 1) {
    const c = header[i];
    if (quoted && c === "\\") { i += 1; continue; } // quoted-pair: skip the escaped char
    if (c === '"') { quoted = !quoted; continue; }
    if (c === "," && !quoted) { out.push(header.slice(start, i)); start = i + 1; }
  }
  out.push(header.slice(start));
  return out;
}

/** RFC 9110 quoted-string: DQUOTE *( qdtext / quoted-pair ) DQUOTE. qdtext
 *  EXCLUDES CTLs — a bare CR/LF/NUL inside a quoted value is malformed, not
 *  content (and a raw CR/LF would be a header-splitting shape). quoted-pair
 *  likewise escapes only HTAB/SP/VCHAR/obs-text. */
const QUOTED_STRING = /^"(?:[\t \x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t \x21-\x7e\x80-\xff])*"$/;

interface CacheEntry {
  readonly registration: CimdRegistration;
  readonly expiresAtMs: number;
}

export class CimdSuccessCache {
  private readonly entries = new Map<string, CacheEntry>();
  private readonly maxEntries: number;
  private lastObservedNowMs: number | undefined;

  constructor(maxEntries: number = DEFAULT_MAX_ENTRIES) {
    this.maxEntries = maxEntries;
  }

  /** A fresh hit; expired entries are evicted on read. LRU order is refreshed
   *  on every hit (re-insert moves the key to the tail). */
  get(key: string, nowMs: number): CimdRegistration | undefined {
    if (!this.observe(nowMs)) return undefined;
    const entry = this.entries.get(key);
    if (entry === undefined) return undefined;
    if (!(nowMs < entry.expiresAtMs)) {
      this.entries.delete(key);
      return undefined;
    }
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.registration;
  }

  set(key: string, registration: CimdRegistration, expiresAtMs: number, observedNowMs: number): void {
    if (!this.observe(observedNowMs) || !Number.isFinite(expiresAtMs)) return;
    this.entries.delete(key);
    while (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done === true) break;
      this.entries.delete(oldest.value);
    }
    this.entries.set(key, { registration, expiresAtMs });
  }

  /** A backward/non-finite injected clock reading invalidates temporal state.
   *  Resetting the observation point avoids both stale resurrection and a
   *  permanent high-water mark after a spurious future clock value. */
  private observe(nowMs: number): boolean {
    const prior = this.lastObservedNowMs;
    this.lastObservedNowMs = Number.isFinite(nowMs) ? nowMs : undefined;
    if (!Number.isFinite(nowMs) || (prior !== undefined && nowMs < prior)) {
      this.entries.clear();
      return false;
    }
    return true;
  }
}

/** RFC-9111 shared-cache freshness (§17.1.6 decision 4), fail-toward-re-fetch.
 *  Returns the absolute expiry in ms, or `null` when the response is NOT
 *  cacheable. A valid `max-age` below 60 is non-cacheable — never clamped up. */
export function computeCacheExpiryMs(
  view: CimdCacheView | undefined, capSeconds: number, t0Ms: number, t1Ms: number,
): number | null {
  if (view === undefined || view.valid !== true) return null;
  const maxAge = parseMaxAge(view.cacheControl);
  if (maxAge === null || hasVaryStar(view.vary)) return null;
  const age = parseAge(view.age);
  if (age === null) return null;
  if (!Number.isFinite(t0Ms) || !Number.isFinite(t1Ms)) return null;
  const responseDelay = t1Ms - t0Ms;
  if (!Number.isFinite(responseDelay) || responseDelay < 0) return null;
  const date = parseDate(view.date);
  if (date === null) return null;
  const apparentAge = date === undefined ? 0 : Math.max(0, t1Ms - date);
  const correctedInitialAge = Math.max(apparentAge, age * 1000 + responseDelay);
  const ttlMs = Math.min(maxAge, capSeconds) * 1000 - correctedInitialAge;
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) return null;
  return t1Ms + ttlMs;
}

/** RFC 9111 `directive = token [ "=" ( token / quoted-string ) ]`. A bare token,
 *  or a fully-terminated quoted-string with no stray unescaped quote. Both
 *  patterns are anchored with bounded classes (ReDoS-safe). */
function isWellFormedDirectiveValue(value: string): boolean {
  if (DIRECTIVE_NAME.test(value.toLowerCase())) return true;
  return QUOTED_STRING.test(value);
}

/** Exactly one `Cache-Control` header occurrence carrying valid shared-cache
 *  freshness. Unsupported or restrictive storage directives refuse storage. Directive
 *  names are ASCII case-insensitive. */
function parseMaxAge(values: readonly string[] | undefined): number | null {
  if (values === undefined || values.length !== 1) return null;
  const header = values[0];
  if (typeof header !== "string") return null;
  let maxAge: number | null = null, sMaxage: number | null = null;
  let maxOccurrences = 0, sMaxOccurrences = 0;
  for (const raw of splitDirectives(header)) {
    const directive = raw.trim();
    if (directive === "") continue;
    const eq = directive.indexOf("=");
    const name = (eq < 0 ? directive : directive.slice(0, eq)).trim().toLowerCase();
    // Rule 25: a MALFORMED Cache-Control ⇒ no cache entry. An unknown but
    // well-formed directive (`foo=bar`) is ignored per RFC 9111; a name that is
    // not a valid RFC 9110 token — including the empty name in `=oops` — is
    // malformed and makes the whole header non-cacheable. Skipping it instead
    // would cache on a header we could not fully parse.
    if (!DIRECTIVE_NAME.test(name)) return null;
    // The VALUE must also be well-formed before we may ignore an unknown
    // directive: `foo==bar` and an unterminated quoted string are malformed
    // headers, and rule 25 makes a malformed Cache-Control non-cacheable.
    // Ignoring only the name would cache on a header we could not fully parse.
    if (eq >= 0 && !isWellFormedDirectiveValue(directive.slice(eq + 1))) return null;
    if (name === "no-store" || name === "no-cache" || name === "private") return null;
    if (name !== "max-age" && name !== "s-maxage") continue;
    if (eq < 0) return null;
    const value = directive.slice(eq + 1);
    if (!UNSIGNED_DECIMAL.test(value)) return null;
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) return null;
    if (name === "max-age") { maxOccurrences += 1; if (maxOccurrences > 1) return null; maxAge = parsed; }
    else { sMaxOccurrences += 1; if (sMaxOccurrences > 1) return null; sMaxage = parsed; }
  }
  const lifetime = sMaxage ?? maxAge;
  return lifetime !== null && lifetime >= MIN_CACHEABLE_MAX_AGE ? lifetime : null;
}

function parseDate(values: readonly string[] | undefined): number | undefined | null {
  if (values === undefined) return undefined;
  if (values.length !== 1 || typeof values[0] !== "string") return null;
  const parsed = Date.parse(values[0]);
  return Number.isFinite(parsed) ? parsed : null;
}

function hasVaryStar(values: readonly string[] | undefined): boolean {
  if (values === undefined) return false;
  return values.some((value) => value.split(",").some((part) => part.trim() === "*"));
}

/** An absent `Age` is 0. A present `Age` is usable only as exactly one
 *  occurrence matching `^[0-9]+$` within the safe-integer bound. */
function parseAge(values: readonly string[] | undefined): number | null {
  if (values === undefined) return 0;
  if (values.length !== 1) return null;
  const value = values[0];
  if (typeof value !== "string" || !UNSIGNED_DECIMAL.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}
