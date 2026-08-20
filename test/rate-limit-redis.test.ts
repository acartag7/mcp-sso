// RedisRateLimit integration: proves distributed limiting (two SEPARATE ioredis
// clients — i.e. two processes — share one window per key) and that the Lua
// EXPIRE-on-first-increment branch actually fires (window resets after
// windowSeconds; TTL is set) — review H4. Constructor validation runs without a
// server. Network tests are gated on REDIS_URL; CI hard-fails if it is missing
// (review B3) so a wiring typo cannot silently skip and print green.

import assert from "node:assert/strict";
import net from "node:net";
import { test } from "node:test";
import { Redis } from "ioredis";
import { RedisRateLimit } from "../src/rate-limit/redis.ts";

const RUN_INTEGRATION = process.env.RUN_INTEGRATION === "true";
const REDIS_URL = process.env.REDIS_URL;
const RUN = !!REDIS_URL;

if (RUN_INTEGRATION && !REDIS_URL) {
  // Keyed on RUN_INTEGRATION (not the ambient CI var): publish.yml runs `pnpm test`
  // under CI=true without the service containers, so gating on CI would block releases.
  throw new Error("REDIS_URL is required when RUN_INTEGRATION is set — the RedisRateLimit adapter must be exercised.");
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

test("RedisRateLimit: a non-NOSCRIPT error on the EVALSHA hot path re-throws for operation policy — review M1", async () => {
  // The hot path tries EVALSHA first. A non-NOSCRIPT error (Redis outage, WRONGTYPE, etc.)
  // must propagate so the consuming operation applies §6.7. This stub exercises the
  // evalsha-throw branch only (the NOSCRIPT->eval-throw branch is covered below).
  const broken = { evalsha: async () => { throw new Error("redis down"); } } as unknown as Redis;
  const rl = new RedisRateLimit(broken, { windowSeconds: 60, limit: 1 });
  await assert.rejects(rl.check("k"), /redis down/);
});

test("RedisRateLimit: if EVALSHA returns NOSCRIPT and EVAL also fails, the EVAL error propagates", async () => {
  // Locks the operation-policy contract on the fallback-also-fails path: NOSCRIPT is
  // the ONLY swallowed error; a failure from the fallback EVAL must NOT be swallowed.
  const broken = {
    evalsha: async () => { throw new Error("NOSCRIPT No matching script. Please use EVAL."); },
    eval: async () => { throw new Error("redis down"); },
  } as unknown as Redis;
  const rl = new RedisRateLimit(broken, { windowSeconds: 60, limit: 1 });
  await assert.rejects(rl.check("k"), /redis down/);
});

// --- non-numeric script replies (§17.10 owner decision D3) ---------------------
// Real ioredis client against a controlled fake RESP server with a PROPER multibulk
// frame parser (a naive line-based stub never reassembles the command frame ioredis
// actually sends). The reply a Redis-compatible facade (proxy, mock, mid-protocol
// rewrite) could produce in place of the INCR integer must THROW — no quota decision
// was reached, so §6.7's outage policy applies — never coerce to an allow. Numeric
// positive controls first prove the instrument itself denies/allows correctly.

type RespResponder = (command: string, items: string[]) => string | undefined;

/** Minimal RESP server: parses one full multibulk command per iteration, asks the
 *  responder for the raw wire reply, writes it. Returns the listening server+port. */
function fakeRespRedis(onCommand: RespResponder): Promise<{ server: net.Server; port: number }> {
  const server = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        const nl = buf.indexOf("\r\n");
        if (nl < 0 || buf[0] !== 42) return; // "*" — multibulk count line incomplete
        const n = Number(buf.subarray(1, nl).toString());
        let off = nl + 2;
        const items: string[] = [];
        for (let i = 0; i < n; i++) {
          const l2 = buf.indexOf("\r\n", off);
          if (l2 < 0 || buf[off] !== 36) return; // "$" — this bulk element incomplete
          const len = Number(buf.subarray(off + 1, l2).toString());
          const start = l2 + 2;
          const end = start + len;
          if (buf.length < end + 2) return; // element body not fully buffered yet
          items.push(buf.subarray(start, end).toString());
          off = end + 2;
        }
        buf = buf.subarray(off);
        const reply = onCommand(items[0]?.toUpperCase() ?? "", items);
        if (reply !== undefined) sock.write(reply);
      }
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, port: (server.address() as net.AddressInfo).port })));
}

test("RedisRateLimit: non-numeric script replies (bulk garbage, null bulk, status) throw; numeric replies decide", async () => {
  const cases: Array<{ label: string; reply: string; expect: boolean | "throw" }> = [
    { label: "control numeric :5 over limit 3", reply: ":5\r\n", expect: false }, // the instrument must deny
    { label: "control numeric :2 within limit", reply: ":2\r\n", expect: true },  // the instrument must allow
    { label: "case bulk garbage 'foo'", reply: "$3\r\nfoo\r\n", expect: "throw" },
    { label: "case null bulk $-1", reply: "$-1\r\n", expect: "throw" }, // Number(null) === 0 — the coerce-to-allow trap
    { label: "case status +OK", reply: "+OK\r\n", expect: "throw" },
  ];
  for (const c of cases) {
    // EVALSHA is answered with NOSCRIPT so the fallback EVAL path is the one scored.
    const { server, port } = await fakeRespRedis((cmd) => (cmd === "EVALSHA" ? "-NOSCRIPT no script\r\n" : c.reply));
    const client = new Redis({ port, host: "127.0.0.1", enableReadyCheck: false, maxRetriesPerRequest: 0, retryStrategy: null, lazyConnect: true, enableOfflineQueue: false });
    const rl = new RedisRateLimit(client, { windowSeconds: 60, limit: 3 });
    try {
      await client.connect();
      if (c.expect === "throw") {
        await assert.rejects(rl.check("register:1.2.3.4"), /non-numeric reply/, `${c.label} → throw`);
      } else {
        assert.equal(await rl.check("register:1.2.3.4"), c.expect, `${c.label} → ${c.expect}`);
      }
    } finally {
      client.disconnect();
      await new Promise<void>((r) => server.close(() => r()));
    }
  }
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
      await Promise.allSettled([a.quit(), b.quit()]);
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

  test("RedisRateLimit: falls back to EVAL on NOSCRIPT and re-caches for subsequent EVALSHA", async () => {
    const client = new Redis(REDIS_URL as string);
    try {
      const prefix = uniquePrefix();
      const limiter = new RedisRateLimit(client, { windowSeconds: 60, limit: 5, keyPrefix: prefix });
      // Warm: prior tests (or this call) have cached the script server-side -> EVALSHA hits.
      assert.equal(await limiter.check("c1"), true);
      // SCRIPT FLUSH drops the cache -> the next check MUST hit NOSCRIPT and fall back to
      // EVAL, which re-loads it so the call after that uses EVALSHA again. Throws if the
      // fallback breaks (the only NOSCRIPT trigger here is the explicit FLUSH).
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
