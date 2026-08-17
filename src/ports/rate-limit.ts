// RateLimitPort — optional DoS defense for unauthenticated OAuth and CIMD
// surfaces (contracts §6.7, fix #7). Bridge/CIMD checks register:<ip>,
// approve:<ip>, token:<ip>, revoke:<ip>, authorize:<ip>, or cimd:<ip> before the
// corresponding work and returns 429 on false. Upstream redirect and submitted
// pairing-code paths additionally use upstream:<ip> and pairing:<ip>. The no-op
// default allows everything; a THROWN error is fail-open (allow). Rate-limiting
// is defense-in-depth against flooding (threat-model #8), NOT a security
// boundary, so an outage must not lock out auth.

export interface RateLimitPort {
  /** true = allow; false = reject with 429. Throw => adapter fails open (allows). */
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
