import assert from "node:assert/strict";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { test } from "node:test";

test("default HTTPS transport explicitly enables certificate verification", async () => {
  const require = createRequire(import.meta.url);
  const https = require("node:https") as typeof import("node:https");
  const mutableHttps = https as { request: typeof https.request };
  const originalRequest = mutableHttps.request;
  let requestOptions: unknown;
  let errorListener: ((error: Error) => void) | undefined;

  mutableHttps.request = ((options: unknown) => {
    requestOptions = options;
    return {
      once(event: string, listener: (error: Error) => void) {
        assert.equal(event, "error");
        errorListener = listener;
        return this;
      },
      end() {
        queueMicrotask(() => errorListener?.(new Error("test transport stop")));
      },
    };
  }) as unknown as typeof https.request;
  syncBuiltinESMExports();

  try {
    const { createGuardedFetcher } = await import(
      `../src/cimd/guarded-fetcher.ts?tls-regression=${Date.now()}`
    );
    const fetcher = createGuardedFetcher({
      resolver: { resolve: async () => [{ address: "93.184.216.34", family: 4 }] },
      fetchTimeoutMs: 1000,
    });
    await assert.rejects(
      () => fetcher.fetch("https://transport.example/client"),
      (error: unknown) => hasReason(error, "fetch_failed"),
    );
    assert.equal(
      (requestOptions as { rejectUnauthorized?: unknown } | undefined)?.rejectUnauthorized,
      true,
    );
  } finally {
    mutableHttps.request = originalRequest;
    syncBuiltinESMExports();
  }
});

test("inherited transport cannot replace the built-in HTTPS transport", async () => {
  const require = createRequire(import.meta.url);
  const https = require("node:https") as typeof import("node:https");
  const mutableHttps = https as { request: typeof https.request };
  const originalRequest = mutableHttps.request;
  let builtInCalls = 0;
  let pollutedCalls = 0;
  let errorListener: ((error: Error) => void) | undefined;

  mutableHttps.request = (() => {
    builtInCalls += 1;
    return {
      once(_event: string, listener: (error: Error) => void) {
        errorListener = listener;
        return this;
      },
      end() {
        queueMicrotask(() => errorListener?.(new Error("test transport stop")));
      },
    };
  }) as unknown as typeof https.request;
  syncBuiltinESMExports();

  try {
    const module = await import(
      `../src/cimd/guarded-fetcher.ts?transport-owncheck=${Date.now()}`
    );
    const previousTransport = Object.getOwnPropertyDescriptor(Object.prototype, "transport");
    Object.defineProperty(Object.prototype, "transport", {
      configurable: true,
      value: {
        connectAndGet() {
          pollutedCalls += 1;
          throw new Error("POLLUTED");
        },
      },
    });

    try {
      const fetcher = module.createGuardedFetcher({
        resolver: { resolve: async () => [{ address: "93.184.216.34", family: 4 }] },
      });
      await assert.rejects(
        () => fetcher.fetch("https://transport.example/client"),
        (error: unknown) => hasReason(error, "fetch_failed"),
      );
      assert.equal(pollutedCalls, 0);
      assert.equal(builtInCalls, 1);
    } finally {
      if (previousTransport === undefined) {
        delete (Object.prototype as Record<string, unknown>).transport;
      } else {
        Object.defineProperty(Object.prototype, "transport", previousTransport);
      }
    }
  } finally {
    mutableHttps.request = originalRequest;
    syncBuiltinESMExports();
  }
});

function hasReason(error: unknown, reason: string): boolean {
  return typeof error === "object" && error !== null
    && "reason" in error && error.reason === reason;
}
