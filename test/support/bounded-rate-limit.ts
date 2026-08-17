import type { RateLimitPort } from "../../src/ports/rate-limit.ts";

/** Finite aggregate budget for tests whose subject is not rate limiting. */
export function boundedTestRateLimit(max = 10_000): RateLimitPort {
  if (!Number.isInteger(max) || max < 1) throw new Error("test rate limit must be positive");
  let remaining = max;
  return Object.freeze({
    async check(): Promise<boolean> {
      if (remaining === 0) return false;
      remaining -= 1;
      return true;
    },
  });
}
