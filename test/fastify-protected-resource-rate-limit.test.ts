import assert from "node:assert/strict";
import { test } from "node:test";
import Fastify from "fastify";
import type {
  FastifyRateLimitOptions,
  FastifyRateLimitStore,
} from "@fastify/rate-limit";
import { AuthConfigError } from "../src/config.ts";
import {
  registerProtectedResourceRateLimit,
} from "../src/adapters/fastify-protected-resource-rate-limit.ts";

function routePolicy(policy: Awaited<ReturnType<typeof registerProtectedResourceRateLimit>>) {
  return { config: { rateLimit: {
    max: policy.max,
    timeWindow: policy.timeWindowMs,
    groupId: policy.groupId,
  } } };
}

test("Fastify protected resource limiter: 429 denial occurs before handler effects", async () => {
  const app = Fastify();
  let effects = 0;
  try {
    const policy = await registerProtectedResourceRateLimit(app, { max: 1, timeWindowMs: 60_000 });
    app.post("/mcp", routePolicy(policy), async () => { effects += 1; return { ok: true }; });

    const admitted = await app.inject({ method: "POST", url: "/mcp" });
    assert.equal(admitted.statusCode, 200);
    const denied = await app.inject({ method: "POST", url: "/mcp" });
    assert.equal(denied.statusCode, 429);
    assert.equal(effects, 1, "the over-budget request never enters the protected handler");
  } finally {
    await app.close();
  }
});

test("Fastify protected resource limiter: custom-store failure is a fixed 503 before handler effects", async () => {
  const privateDetail = "backend store failed at a private address";
  class ThrowingStore implements FastifyRateLimitStore {
    constructor(_options: FastifyRateLimitOptions) {}
    incr(
      _key: string,
      callback: (error: Error | null, result?: { current: number; ttl: number }) => void,
    ): void { callback(new Error(privateDetail)); }
    child(): FastifyRateLimitStore { return this; }
  }

  const app = Fastify();
  let effects = 0;
  try {
    const policy = await registerProtectedResourceRateLimit(app, { store: ThrowingStore });
    app.post("/mcp", routePolicy(policy), async () => { effects += 1; return { ok: true }; });

    const response = await app.inject({ method: "POST", url: "/mcp" });
    assert.equal(response.statusCode, 503);
    assert.equal(effects, 0);
    assert.match(response.body, /Protected resource rate limiter unavailable/);
    assert.doesNotMatch(response.body, new RegExp(privateDetail), "store internals never reach the client");
  } finally {
    await app.close();
  }
});

test("Fastify protected resource limiter: child-store failure is a fixed 503", async () => {
  class ChildFailureStore implements FastifyRateLimitStore {
    constructor(_options: FastifyRateLimitOptions) {}
    incr(_key: string, callback: (error: Error | null) => void): void { callback(null); }
    child(): FastifyRateLimitStore {
      return {
        incr(_key, callback) { callback(new Error("child store detail")); },
        child() { return this; },
      };
    }
  }
  const app = Fastify();
  let effects = 0;
  try {
    const policy = await registerProtectedResourceRateLimit(app, { store: ChildFailureStore });
    app.post("/mcp", routePolicy(policy), async () => { effects += 1; return { ok: true }; });
    const response = await app.inject({ method: "POST", url: "/mcp" });
    assert.equal(response.statusCode, 503);
    assert.equal(effects, 0);
    assert.doesNotMatch(response.body, /child store detail/);
  } finally {
    await app.close();
  }
});

test("Fastify protected resource limiter: malformed counters fail closed", async () => {
  const malformed = [
    { current: 1.5, ttl: 1_000 },
    { current: 1, ttl: 1.5 },
    { current: Number.MAX_SAFE_INTEGER + 1, ttl: 1_000 },
    { current: "1", ttl: 1_000 },
    { current: 1, ttl: null },
    Object.defineProperty({}, "current", { get() { throw new Error("counter getter detail"); } }),
  ];
  for (const result of malformed) {
    class MalformedStore implements FastifyRateLimitStore {
      constructor(_options: FastifyRateLimitOptions) {}
      incr(_key: string, callback: (error: Error | null, value?: { current: number; ttl: number }) => void): void {
        callback(null, result as never);
      }
      child(): FastifyRateLimitStore { return this; }
    }
    const app = Fastify();
    try {
      const policy = await registerProtectedResourceRateLimit(app, { store: MalformedStore });
      app.post("/mcp", routePolicy(policy), async () => ({ ok: true }));
      const response = await app.inject({ method: "POST", url: "/mcp" });
      assert.equal(response.statusCode, 503);
      assert.doesNotMatch(response.body, /counter getter detail/);
    } finally {
      await app.close();
    }
  }
});

test("Fastify protected resource limiter: the first store callback is single-shot", async () => {
  class NoisyStore implements FastifyRateLimitStore {
    constructor(_options: FastifyRateLimitOptions) {}
    incr(_key: string, callback: (error: Error | null, result?: { current: number; ttl: number }) => void): void {
      callback(null, { current: 1, ttl: 60_000 });
      callback(new Error("late callback detail"));
      throw new Error("late throw detail");
    }
    child(): FastifyRateLimitStore { return this; }
  }
  const app = Fastify();
  let effects = 0;
  try {
    const policy = await registerProtectedResourceRateLimit(app, { store: NoisyStore });
    app.post("/mcp", routePolicy(policy), async () => { effects += 1; return { ok: true }; });
    const response = await app.inject({ method: "POST", url: "/mcp" });
    assert.equal(response.statusCode, 200);
    assert.equal(effects, 1);
  } finally {
    await app.close();
  }
});

test("Fastify protected resource limiter: malformed policy rejects at registration", async () => {
  for (const options of [
    null,
    { max: 0 },
    { max: 10_001 },
    { timeWindowMs: 999 },
    { timeWindowMs: 3_600_001 },
    { unknown: true },
    { store: {} },
    Object.defineProperty({}, "max", { get() { throw new Error("option getter detail"); } }),
    new Proxy({}, { ownKeys() { throw new Error("ownKeys detail"); } }),
  ]) {
    const app = Fastify();
    try {
      await assert.rejects(
        registerProtectedResourceRateLimit(app, options as never),
        AuthConfigError,
      );
    } finally {
      await app.close();
    }
  }
});
