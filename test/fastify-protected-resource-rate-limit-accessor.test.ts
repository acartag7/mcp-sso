import assert from "node:assert/strict";
import { test } from "node:test";
import Fastify from "fastify";
import type {
  FastifyRateLimitOptions,
  FastifyRateLimitStore,
  FastifyRateLimitStoreCtor,
} from "@fastify/rate-limit";
import {
  registerProtectedResourceRateLimit,
} from "../src/adapters/fastify-protected-resource-rate-limit.ts";

type Counter = { current: number; ttl: number };
type CounterReads = { current: number; ttl: number };
type CounterBehavior = {
  current(read: number): number;
  ttl(read: number): number;
};
type StorePath = "root" | "child";

function accessorCounter(behavior: CounterBehavior, reads: CounterReads): Counter {
  return Object.defineProperties({}, {
    current: {
      enumerable: true,
      get() {
        reads.current += 1;
        return behavior.current(reads.current);
      },
    },
    ttl: {
      enumerable: true,
      get() {
        reads.ttl += 1;
        return behavior.ttl(reads.ttl);
      },
    },
  }) as Counter;
}

function counterStore(result: () => Counter): FastifyRateLimitStoreCtor {
  return class implements FastifyRateLimitStore {
    constructor(_options: FastifyRateLimitOptions) {}

    incr(_key: string, callback: (error: Error | null, value?: Counter) => void): void {
      callback(null, result());
    }

    child(): FastifyRateLimitStore {
      return {
        incr(_key, callback) { callback(null, result()); },
        child() { return this; },
      };
    }
  };
}

async function requestThrough(
  path: StorePath,
  behavior: CounterBehavior,
  reads: CounterReads,
): Promise<{ statusCode: number; body: string; effects: number }> {
  const app = Fastify();
  let effects = 0;
  try {
    const policy = await registerProtectedResourceRateLimit(app, {
      store: counterStore(() => accessorCounter(behavior, reads)),
    });
    const handler = async () => { effects += 1; return { ok: true }; };
    if (path === "child") {
      app.post("/mcp", { config: { rateLimit: {
        max: policy.max,
        timeWindow: policy.timeWindowMs,
        groupId: policy.groupId,
      } } }, handler);
    } else {
      await app.register(async (instance) => {
        instance.post("/mcp", { onRequest: instance.rateLimit() }, handler);
      });
    }
    const response = await app.inject({ method: "POST", url: "/mcp" });
    return { statusCode: response.statusCode, body: response.body, effects };
  } finally {
    await app.close();
  }
}

const rejectionCases: Array<{
  name: string;
  behavior: CounterBehavior;
  expectedReads: CounterReads;
}> = [
  {
    name: "current changes from invalid to valid",
    behavior: { current: (read) => read === 1 ? 0 : 1, ttl: () => 60_000 },
    expectedReads: { current: 1, ttl: 1 },
  },
  {
    name: "ttl changes from invalid to valid",
    behavior: { current: () => 1, ttl: (read) => read === 1 ? -1 : 60_000 },
    expectedReads: { current: 1, ttl: 1 },
  },
  {
    name: "current throws",
    behavior: { current: () => { throw new Error("current accessor detail"); }, ttl: () => 60_000 },
    expectedReads: { current: 1, ttl: 0 },
  },
  {
    name: "ttl throws",
    behavior: { current: () => 1, ttl: () => { throw new Error("ttl accessor detail"); } },
    expectedReads: { current: 1, ttl: 1 },
  },
];

for (const path of ["root", "child"] as const) {
  test(`Fastify protected resource limiter snapshots invalid and throwing ${path} accessors`, async () => {
    for (const entry of rejectionCases) {
      const reads = { current: 0, ttl: 0 };
      const response = await requestThrough(path, entry.behavior, reads);
      assert.equal(response.statusCode, 503, entry.name);
      assert.equal(response.effects, 0, `${entry.name} stays before handler effects`);
      assert.match(response.body, /Protected resource rate limiter unavailable/);
      assert.doesNotMatch(response.body, /accessor detail/);
      assert.deepEqual(reads, entry.expectedReads, `${entry.name} is not re-read`);
    }
  });

  test(`Fastify protected resource limiter returns only valid ${path} snapshots`, async () => {
    const reads = { current: 0, ttl: 0 };
    const response = await requestThrough(path, {
      current: (read) => read === 1 ? 1 : 0,
      ttl: (read) => {
        if (read === 1) return 60_000;
        throw new Error("post-snapshot ttl detail");
      },
    }, reads);
    assert.equal(response.statusCode, 200, `${path}: first snapshots remain authoritative`);
    assert.equal(response.effects, 1);
    assert.deepEqual(reads, { current: 1, ttl: 1 }, `${path}: valid fields are read once`);
  });
}
