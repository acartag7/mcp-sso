// Supplementary (non-frozen) tests for createGuardedFetcher option validation
// (Fable review of PR #87). A misspelled/unknown cap key must fail closed rather
// than be silently ignored (which would use the default cap) — the repo's binding
// fail-closed configuration rule.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createGuardedFetcher } from "../src/cimd/guarded-fetcher.ts";
import { admitCimdUrl } from "../src/cimd/admission.ts";
import { isBlockedAddress } from "../src/cimd/blocklist.ts";

test("createGuardedFetcher rejects unknown / misspelled option keys (fail-closed config)", () => {
  assert.throws(() => createGuardedFetcher({ unknown: true } as never));
  assert.throws(() => createGuardedFetcher({ maxDocumentByte: 1024 } as never)); // typo: missing 's'
  assert.throws(() => createGuardedFetcher({ fetchTimeoutMS: 1000 } as never)); // typo: wrong case
});

test("createGuardedFetcher accepts exactly the documented option keys", () => {
  assert.doesNotThrow(() =>
    createGuardedFetcher({ allowLoopback: true, maxDocumentBytes: 2048, fetchTimeoutMs: 2000 }));
});

test("prototype state cannot enable loopback admission or transport", async () => {
  const previous = Object.getOwnPropertyDescriptor(Object.prototype, "allowLoopback");
  Object.defineProperty(Object.prototype, "allowLoopback", {
    configurable: true, enumerable: true, value: true, writable: true,
  });
  try {
    assert.throws(
      () => admitCimdUrl("https://localhost/client"),
      (error: unknown) => hasReason(error, "url_admission_denied"),
    );
    assert.equal(isBlockedAddress("127.0.0.1"), true);

    let transportCalls = 0;
    const fetcher = createGuardedFetcher({
      resolver: { resolve: async () => [{ address: "127.0.0.1", family: 4 }] },
      transport: {
        connectAndGet: async () => {
          transportCalls += 1;
          throw new Error("transport must not run");
        },
      },
    });
    await assert.rejects(
      () => fetcher.fetch("https://localhost/client"),
      (error: unknown) => hasReason(error, "url_admission_denied"),
    );
    await assert.rejects(
      () => fetcher.fetch("https://public.example/client"),
      (error: unknown) => hasReason(error, "ip_blocked"),
    );
    assert.equal(transportCalls, 0);
  } finally {
    if (previous === undefined) {
      delete (Object.prototype as Record<string, unknown>).allowLoopback;
    } else {
      Object.defineProperty(Object.prototype, "allowLoopback", previous);
    }
  }
});

function hasReason(error: unknown, reason: string): boolean {
  return typeof error === "object" && error !== null
    && "reason" in error && error.reason === reason;
}
