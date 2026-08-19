// RateLimitPort — optional DoS defense for unauthenticated OAuth and CIMD
// surfaces (contracts §6.7, fix #7). Bridge/CIMD checks register:<ip>,
// approve:<ip>, token:<ip>, revoke:<ip>, authorize:<ip>, or cimd:<ip> before the
// corresponding work and returns 429 on false. Upstream redirect and submitted
// pairing-code paths additionally use upstream:<ip> and pairing:<ip>; the latter
// returns `pairing_rate_limited` instead of 429. The no-op default allows
// everything. A THROWN error fails closed only for stored-mode
// registration, whose anonymous durable write makes limiter availability part
// of admission; every continuity operation and stateless registration remains
// fail-open (threat-model #8, contracts §6.7).

export interface RateLimitPort {
  /** true = allow; false = the caller's denial outcome (guard 429 or pairing
   *  failure). Throw => §6.7: stored registration rejects with 503; others allow. */
  check(key: string): Promise<boolean>;
}

// Bound boot snapshots must keep the identity of their source port: the shared
// CIMD resolver uses identity to avoid charging one counting limiter twice when
// a composition passes it to both Bridge and the upstream flow.
const RATE_LIMIT_IDENTITIES = new WeakMap<RateLimitPort, RateLimitPort>();

export function rateLimitIdentity(port: RateLimitPort): RateLimitPort {
  return RATE_LIMIT_IDENTITIES.get(port) ?? port;
}

export function recordRateLimitSnapshot(snapshot: RateLimitPort, source: RateLimitPort): void {
  RATE_LIMIT_IDENTITIES.set(snapshot, rateLimitIdentity(source));
}

/** Default no-op limiter: allows everything. It is valid only in compositions
 *  admitted by the deployment guard; stored DCR requires a bounded port. */
export const noopRateLimit: RateLimitPort = {
  async check(): Promise<boolean> {
    return true;
  },
};
