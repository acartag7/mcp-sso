// RedisRateLimit — distributed RateLimitPort on Redis/Valkey (contracts §6.7, §17.10).
// A fixed-window counter per key: one Lua script does INCR + EXPIRE-on-first-
// increment atomically (Redis runs Lua single-threaded, so two concurrent first-
// incrementers cannot both see n==1 and the TTL is set exactly once per window).
// check() THROWS on any Redis error — the bridge's guard() catches that and fails
// OPEN (availability over advisory defense; §6.7 "Throw => adapter fails open",
// §17.10 "failure semantics UNCHANGED"). Rate-limiting is DoS defense-in-depth
// (threat-model #8), NOT a security boundary, so an outage must not lock out auth.

import type { Redis } from "ioredis";
import type { RateLimitPort } from "../ports/rate-limit.ts";

export interface RedisRateLimitConfig {
  /** Fixed-window length in seconds. Must be a positive integer. */
  windowSeconds: number;
  /** Requests allowed per window per key. Must be a positive integer. */
  limit: number;
  /** Key namespace (the bridge passes logical keys like "register:<ip>"). Defaults
   *  to "mcp-sso:rl:" so a shared Redis is isolated. Must not collide with non-string
   *  keys (a WRONGTYPE collision degrades to fail-open — safe direction). */
  keyPrefix?: string;
}

// Atomic INCR + EXPIRE-on-first-increment. Returns the counter value after INCR.
const FIXED_WINDOW_LUA = [
  "local n = redis.call('INCR', KEYS[1])",
  "if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end",
  "return n",
].join("\n");

export class RedisRateLimit implements RateLimitPort {
  private readonly client: Redis;
  private readonly windowSeconds: number;
  private readonly limit: number;
  private readonly keyPrefix: string;

  constructor(client: Redis, config: RedisRateLimitConfig) {
    if (!Number.isInteger(config.windowSeconds) || config.windowSeconds < 1) {
      throw new Error("RedisRateLimitConfig.windowSeconds must be a positive integer");
    }
    if (!Number.isInteger(config.limit) || config.limit < 1) {
      throw new Error("RedisRateLimitConfig.limit must be a positive integer");
    }
    this.client = client;
    this.windowSeconds = config.windowSeconds;
    this.limit = config.limit;
    this.keyPrefix = config.keyPrefix ?? "mcp-sso:rl:";
  }

  async check(key: string): Promise<boolean> {
    // Throws on Redis outage / WRONGTYPE / eval failure -> bridge guard() fails open.
    const count = await this.client.eval(FIXED_WINDOW_LUA, 1, this.keyPrefix + key, this.windowSeconds);
    return Number(count) <= this.limit;
  }
}

export function createRedisRateLimit(client: Redis, config: RedisRateLimitConfig): RedisRateLimit {
  return new RedisRateLimit(client, config);
}
