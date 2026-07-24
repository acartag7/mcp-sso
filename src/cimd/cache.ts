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

interface CacheEntry {
  readonly registration: CimdRegistration;
  readonly expiresAtMs: number;
}

export class CimdSuccessCache {
  private readonly entries = new Map<string, CacheEntry>();
  private readonly maxEntries: number;

  constructor(maxEntries: number = DEFAULT_MAX_ENTRIES) {
    this.maxEntries = maxEntries;
  }

  /** A fresh hit; expired entries are evicted on read. LRU order is refreshed
   *  on every hit (re-insert moves the key to the tail). */
  get(key: string, nowMs: number): CimdRegistration | undefined {
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

  set(key: string, registration: CimdRegistration, expiresAtMs: number): void {
    this.entries.delete(key);
    while (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done === true) break;
      this.entries.delete(oldest.value);
    }
    this.entries.set(key, { registration, expiresAtMs });
  }
}

/** RFC-9111-correct freshness (§17.1.6 decision 4), fail-toward-re-fetch:
 *  `effectiveTtlSeconds = min(valid max-age, cap) − Age − elapsedSeconds`.
 *  Returns the absolute expiry in ms, or `null` when the response is NOT
 *  cacheable. A valid `max-age` below 60 is non-cacheable — never clamped up. */
export function computeCacheExpiryMs(
  view: CimdCacheView | undefined, capSeconds: number, t0Ms: number, t1Ms: number,
): number | null {
  if (view === undefined) return null;
  const maxAge = parseMaxAge(view.cacheControl);
  if (maxAge === null || maxAge < MIN_CACHEABLE_MAX_AGE) return null;
  const age = parseAge(view.age);
  if (age === null) return null;
  if (!Number.isFinite(t0Ms) || !Number.isFinite(t1Ms)) return null;
  const elapsedSeconds = Math.floor((t1Ms - t0Ms) / 1000);
  if (!Number.isFinite(elapsedSeconds) || elapsedSeconds < 0) return null;
  const ttlSeconds = Math.min(maxAge, capSeconds) - age - elapsedSeconds;
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) return null;
  return t1Ms + ttlSeconds * 1000;
}

/** Exactly one `Cache-Control` header occurrence carrying exactly one
 *  `max-age` directive with an unquoted unsigned-decimal safe-integer value,
 *  and no `no-store`/`no-cache`. Anything else ⇒ non-cacheable. Directive
 *  names are ASCII case-insensitive. */
function parseMaxAge(values: readonly string[] | undefined): number | null {
  if (values === undefined || values.length !== 1) return null;
  const header = values[0];
  if (typeof header !== "string") return null;
  let maxAge: number | null = null;
  let occurrences = 0;
  for (const raw of header.split(",")) {
    const directive = raw.trim();
    if (directive === "") continue;
    const eq = directive.indexOf("=");
    const name = (eq < 0 ? directive : directive.slice(0, eq)).trim().toLowerCase();
    if (name === "no-store" || name === "no-cache") return null;
    if (name !== "max-age") continue;
    occurrences += 1;
    if (occurrences > 1) return null;
    if (eq < 0) return null;
    const value = directive.slice(eq + 1);
    if (!UNSIGNED_DECIMAL.test(value)) return null;
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) return null;
    maxAge = parsed;
  }
  return occurrences === 1 ? maxAge : null;
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
