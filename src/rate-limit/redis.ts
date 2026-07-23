// RedisRateLimit — distributed RateLimitPort on Redis/Valkey (contracts §6.7, §17.10).
// A fixed-window counter per key: one Lua script does INCR + EXPIRE-on-first-
// increment atomically (Redis runs Lua single-threaded, so two concurrent first-
// incrementers cannot both see n==1 and the TTL is set exactly once per window).
// The hot path uses EVALSHA (one round-trip carries only the SHA1, not the script
// body); on NOSCRIPT — Redis restarted or SCRIPT FLUSH — it falls back to EVAL,
// which re-loads the script for next time. Atomicity and fail-open are identical
// either way. check() THROWS on any OTHER Redis error — the bridge's guard()
// catches that and fails OPEN (availability over advisory defense; §6.7 "Throw =>
// adapter fails open", §17.10 "failure semantics UNCHANGED"). Rate-limiting is DoS
// defense-in-depth (threat-model #8), NOT a security boundary.

import { createHash } from "node:crypto";
import type { Redis } from "ioredis";
import type { RateLimitPort } from "../ports/rate-limit.ts";
import { ownDataValue, snapshotOwnDataRecord } from "../own-property.ts";

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
// SHA1 of the script body — Redis caches compiled scripts by this hash (SCRIPT LOAD),
// so EVALSHA runs the cached script without re-sending the body. Computed once.
const FIXED_WINDOW_SHA = createHash("sha1").update(FIXED_WINDOW_LUA).digest("hex");

export class RedisRateLimit implements RateLimitPort {
  private readonly client: Redis;
  private readonly windowSeconds: number;
  private readonly limit: number;
  private readonly keyPrefix: string;

  constructor(client: Redis, config: RedisRateLimitConfig) {
    const fields = snapshotOwnDataRecord(config);
    if (fields === null) throw new TypeError("RedisRateLimitConfig must use own data properties");
    if (!Number.isInteger(fields.windowSeconds) || (fields.windowSeconds as number) < 1) {
      throw new Error("RedisRateLimitConfig.windowSeconds must be a positive integer");
    }
    if (!Number.isInteger(fields.limit) || (fields.limit as number) < 1) {
      throw new Error("RedisRateLimitConfig.limit must be a positive integer");
    }
    this.client = client;
    if (fields.keyPrefix !== undefined && typeof fields.keyPrefix !== "string") {
      throw new Error("RedisRateLimitConfig.keyPrefix must be a string");
    }
    this.windowSeconds = fields.windowSeconds as number;
    this.limit = fields.limit as number;
    this.keyPrefix = (fields.keyPrefix as string | undefined) ?? "mcp-sso:rl:";
  }

  async check(key: string): Promise<boolean> {
    const fullKey = this.keyPrefix + key;
    let count: unknown;
    try {
      count = await this.client.evalsha(FIXED_WINDOW_SHA, 1, fullKey, this.windowSeconds);
    } catch (error) {
      // NOSCRIPT = Redis has no cached copy of the script (restart / FLUSH). Fall back
      // to EVAL, which re-loads it; subsequent calls use EVALSHA again. This is the ONLY
      // swallowed error — any other failure propagates so guard() fails open.
      if (!isNoScript(error)) throw error;
      count = await this.client.eval(FIXED_WINDOW_LUA, 1, fullKey, this.windowSeconds);
    }
    // Fail-open on a non-numeric reply (defensive — unreachable in practice: the script
    // always returns the INCR integer; ioredis rejects on connection loss) to match the
    // throw -> fail-open posture of §6.7/§17.10 rather than deny (NaN <= limit is false).
    const n = Number(count);
    return Number.isFinite(n) ? n <= this.limit : true;
  }
}

export function createRedisRateLimit(client: Redis, config: RedisRateLimitConfig): RedisRateLimit {
  return new RedisRateLimit(client, config);
}

// ioredis surfaces Redis's NOSCRIPT error as a ReplyError whose message begins with
// "NOSCRIPT" (there is no `.code` field — verified against ioredis 5.11 / Redis 7).
function isNoScript(error: unknown): boolean {
  const message = ownDataValue(error, "message");
  return typeof message === "string" && message.startsWith("NOSCRIPT");
}
