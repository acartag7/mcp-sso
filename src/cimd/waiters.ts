// Per-in-flight-entry follower accounting (§17.1.6 decision 7).
//
// `maxInFlight` bounds concurrent OUTBOUND fetches; it does NOT bound the
// inbound callers parked on one of them. Single-flight correctly collapses N
// concurrent requests for one raw client_id into ONE fetch — and rule 24
// deliberately exempts followers from consuming a fetch slot so a popular
// client cannot starve distinct client_ids — but the follower REQUESTS still
// exist, each holding a socket, a promise chain and a closure for up to
// `fetchTimeoutMs`. Measured before this bound existed: 10 000 concurrent
// same-id resolutions ⇒ 1 fetch, ~15.4 MB retained, from an UNAUTHENTICATED
// caller (CIMD resolution runs before any IdP redirect). That is CWE-770.
//
// Counts are keyed by the RAW client_id, never a parsed/normalized URL — a
// global counter would let one client_id deny followers for unrelated ones.

/** Tracks how many followers are parked on each in-flight raw client_id. */
export class WaiterCounts {
  readonly #counts = new Map<string, number>();

  /** Reserve a follower slot, or return false when the entry is at its cap.
   *  A REFUSED caller never acquires a slot, so it must not later release one:
   *  freeing capacity it never took would admit the next follower while the
   *  original fetch and its in-cap followers are still parked. */
  tryAcquire(key: string, max: number): boolean {
    const parked = this.#counts.get(key) ?? 0;
    if (parked >= max) return false;
    this.#counts.set(key, parked + 1);
    return true;
  }

  /** Release a slot acquired by `tryAcquire`. Call on EVERY exit — success,
   *  error, and timeout/cancellation (rule 24's three settle paths). */
  release(key: string): void {
    const left = (this.#counts.get(key) ?? 1) - 1;
    if (left <= 0) this.#counts.delete(key);
    else this.#counts.set(key, left);
  }
}
