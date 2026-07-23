// RateLimitPort — optional DoS defense for unauthenticated registration, token,
// and header-driven identity verification (contracts §6.7, threat-model #8).
// The bridge checks register:<ip>, token:<ip>, or authorize:<ip> before the
// corresponding work and returns 429 on false. The no-op default allows
// everything; a THROWN error is treated as fail-open (allow) because limiting
// is defense-in-depth against flooding, NOT an authentication boundary.

export interface RateLimitPort {
  /** true = allow; false = reject with 429. Throw => bridge fails open (allows). */
  check(key: string): Promise<boolean>;
}

/** Default no-op limiter: allows everything. Inject a real implementation
 *  (e.g. a per-IP token bucket) at the composition root. */
export const noopRateLimit: RateLimitPort = {
  async check(): Promise<boolean> {
    return true;
  },
};
