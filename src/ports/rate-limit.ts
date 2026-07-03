// RateLimitPort — optional DoS defense for the unauthenticated /oauth/register
// and /oauth/token endpoints (contracts §6.7, fix #7). A framework adapter calls
// check("register:<ip>") / check("token:<ip>") before the use-case and returns
// 429 on false. The no-op default allows everything; a THROWN error is treated by
// the adapter as fail-open (allow) — rate-limiting is defense-in-depth against
// flooding (threat-model #8), NOT a security boundary, so an outage must not lock
// out all auth.

export interface RateLimitPort {
  /** true = allow; false = reject with 429. Throw => adapter fails open (allows). */
  check(key: string): Promise<boolean>;
}

/** Default no-op limiter: allows everything. Inject a real implementation
 *  (e.g. a per-IP token bucket) at the composition root. */
export const noopRateLimit: RateLimitPort = {
  async check(): Promise<boolean> {
    return true;
  },
};
