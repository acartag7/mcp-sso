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
      (error: unknown) => error instanceof Error
        && (error as { reason?: unknown }).reason === "fetch_failed",
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
