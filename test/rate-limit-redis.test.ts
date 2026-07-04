// RedisRateLimit integration: proves distributed limiting (two SEPARATE ioredis
// clients — i.e. two processes — share one window per key) and that the Lua
// EXPIRE-on-first-increment branch actually fires (window resets after
// windowSeconds; TTL is set) — review H4. Constructor validation runs without a
// server. Network tests are gated on REDIS_URL; CI hard-fails if it is missing
// (review B3) so a wiring typo cannot silently skip and print green.

import assert from "node:assert/strict";
import { test } from "node:test";
import { Redis } from "ioredis";
import { RedisRateLimit } from "../src/rate-limit/redis.ts";

const CI = process.env.CI === "true";
const REDIS_URL = process.env.REDIS_URL;
const RUN = !!REDIS_URL;

if (CI && !REDIS_URL) {
  throw new Error("REDIS_URL is required in CI — the RedisRateLimit adapter must be exercised.");
}

const sleep = (ms: number): Promise<void> => new Promise((r) => { setTimeout(r, ms); });

// Unique per-process, per-run, per-call namespace so re-runs and parallel tests
// never share or contaminate a key (review M6). Never reuses the bridge's prefix.
let counter = 0;
function uniquePrefix(): string {
  return `test:${process.pid}:${Date.now()}:${counter++}:`;
}

test("RedisRateLimit: rejects non-positive windowSeconds/limit at construction (fail-closed config)", () => {
  const stub = {} as Redis;
  assert.throws(() => new RedisRateLimit(stub, { windowSeconds: 0, limit: 1 }));
  assert.throws(() => new RedisRateLimit(stub, { windowSeconds: 1, limit: 0 }));
  assert.throws(() => new RedisRateLimit(stub, { windowSeconds: -1, limit: 1 }));
  assert.throws(() => new RedisRateLimit(stub, { windowSeconds: 1.5, limit: 1 }));
  assert.throws(() => new RedisRateLimit(stub, { windowSeconds: 1, limit: 1.5 }));
});

test("RedisRateLimit: check() THROWS on Redis error so the bridge guard() fails open (§6.7/§17.10) — review M1", async () => {
  // A Redis outage must surface as a throw (not a swallow/return-false), so the bridge's
  // guard() catches it and allows the request. This locks the fail-open contract directly
  // against the real adapter (the bridge test uses a stub). The hot path tries EVALSHA
  // first, so the stub rejects on both evalsha and eval.
  const broken = {
    evalsha: async () => { throw new Error("redis down"); },
    eval: async () => { throw new Error("redis down"); },
  } as unknown as Redis;
  const rl = new RedisRateLimit(broken, { windowSeconds: 60, limit: 1 });
  await assert.rejects(rl.check("k"), /redis down/);
});

if (RUN) {
  test("RedisRateLimit: two clients share a window (distributed limiting — a per-process limiter would NOT pass this)", async () => {
    const a = new Redis(REDIS_URL as string);
    const b = new Redis(REDIS_URL as string);
    try {
      const prefix = uniquePrefix();
      const key = "register:9.9.9.9";
      const la = new RedisRateLimit(a, { windowSeconds: 60, limit: 2, keyPrefix: prefix });
      const lb = new RedisRateLimit(b, { windowSeconds: 60, limit: 2, keyPrefix: prefix });
      assert.equal(await clientExists(a, prefix + key), 0, "key must not pre-exist");
      assert.equal(await la.check(key), true);  // n=1
      assert.equal(await lb.check(key), true);  // n=2 — shared window across clients
      assert.equal(await la.check(key), false); // n=3 > limit
    } finally {
      await a.quit();
      await b.quit();
    }
  });

  test("RedisRateLimit: window resets after windowSeconds (EXPIRE fires on first increment) — review H4", async () => {
    const client = new Redis(REDIS_URL as string);
    try {
      const prefix = uniquePrefix();
      const key = "token:8.8.8.8";
      const limiter = new RedisRateLimit(client, { windowSeconds: 2, limit: 2, keyPrefix: prefix });
      assert.equal(await clientExists(client, prefix + key), 0, "key must not pre-exist");
      assert.equal(await limiter.check(key), true);  // n=1 -> EXPIRE 2 (fixed-window: TTL set ONCE here)
      await sleep(1300);                              // ~0.7s left in the window
      assert.equal(await limiter.check(key), true);  // n=2 — a SLIDING-window bug would reset TTL to 2 here
      const ttlMid = await client.ttl(prefix + key);
      assert.ok(ttlMid <= 1, `ttl must NOT reset on the 2nd increment (fixed window); got ${ttlMid}`);
      assert.equal(await limiter.check(key), false); // n=3 > limit
      await sleep(1100);                              // window elapses -> key expires
      assert.equal(await limiter.check(key), true);  // fresh window, n=1 again
      const ttlReset = await client.ttl(prefix + key);
      assert.ok(ttlReset > 0 && ttlReset <= 2, `ttl should be reset after the window, got ${ttlReset}`);
    } finally {
      await client.quit();
    }
  });

  test("RedisRateLimit: uses EVALSHA on the hot path and falls back to EVAL on NOSCRIPT (perf)", async () => {
    const client = new Redis(REDIS_URL as string);
    try {
      const prefix = uniquePrefix();
      const limiter = new RedisRateLimit(client, { windowSeconds: 60, limit: 5, keyPrefix: prefix });
      // Cold start: EVALSHA misses (NOSCRIPT) -> EVAL fallback loads the script.
      assert.equal(await limiter.check("c1"), true);
      // SCRIPT FLUSH drops the cache -> the next check MUST hit NOSCRIPT and fall back,
      // then re-cache so subsequent calls use EVALSHA again. Throws if the fallback breaks.
      await client.script("FLUSH");
      assert.equal(await limiter.check("c2"), true);
      assert.equal(await limiter.check("c3"), true);
    } finally {
      await client.quit();
    }
  });
}

async function clientExists(client: Redis, key: string): Promise<number> {
  return client.exists(key);
}
