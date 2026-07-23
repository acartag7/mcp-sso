// Supplementary (non-frozen) tests for createGuardedFetcher option validation.
// A misspelled/unknown cap key must fail closed rather than be silently ignored
// (which would use the default cap) — the repo's binding fail-closed rule.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createGuardedFetcher, type GuardedFetcher } from "../src/cimd/guarded-fetcher.ts";
import { admitCimdUrl } from "../src/cimd/admission.ts";
import { isBlockedAddress } from "../src/cimd/blocklist.ts";

// @ts-expect-error — the unexported unique-symbol brand makes this nominal.
const plainFetcher: GuardedFetcher = { async fetch() { throw new Error("unused"); } };
void plainFetcher;

test("createGuardedFetcher rejects unknown / misspelled option keys (fail-closed config)", () => {
  assert.throws(() => createGuardedFetcher({ unknown: true } as never));
  assert.throws(() => createGuardedFetcher({ maxDocumentByte: 1024 } as never)); // typo: missing 's'
  assert.throws(() => createGuardedFetcher({ fetchTimeoutMS: 1000 } as never)); // typo: wrong case
});

test("createGuardedFetcher accepts exactly the documented option keys", () => {
  assert.doesNotThrow(() =>
    createGuardedFetcher({ allowLoopback: true, maxDocumentBytes: 2048, fetchTimeoutMs: 2000 }));
});

test("option descriptor lookup cannot fall back to Object.prototype", () => {
  const previous = Object.getOwnPropertyDescriptor(Object.prototype, "fetchTimeoutMs");
  Object.defineProperty(Object.prototype, "fetchTimeoutMs", {
    configurable: true, value: { value: null },
  });
  try {
    assert.doesNotThrow(() => createGuardedFetcher({}));
  } finally {
    if (previous === undefined) delete (Object.prototype as Record<string, unknown>).fetchTimeoutMs;
    else Object.defineProperty(Object.prototype, "fetchTimeoutMs", previous);
  }
});

test("options with own data fields remain compatible with class instances", () => {
  class Options {
    fetchTimeoutMs = 1000;
    maxDocumentBytes = 5120;
  }
  assert.doesNotThrow(() => createGuardedFetcher(new Options()));
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
    if (previous === undefined) delete (Object.prototype as { allowLoopback?: unknown }).allowLoopback;
    else Object.defineProperty(Object.prototype, "allowLoopback", previous);
  }
});

test("option accessors and unsupported own keys reject without invoking getters", () => {
  let getterCalls = 0;
  const accessor = {} as { allowLoopback?: boolean };
  Object.defineProperty(accessor, "allowLoopback", {
    enumerable: true,
    get() { getterCalls += 1; return true; },
  });
  assert.throws(() => createGuardedFetcher(accessor));
  assert.equal(getterCalls, 0);

  assert.throws(() => createGuardedFetcher({ [Symbol("option")]: true } as never));

  const hiddenUnknown = {};
  Object.defineProperty(hiddenUnknown, "unknown", { enumerable: false, value: true });
  assert.throws(() => createGuardedFetcher(hiddenUnknown as never));
});

test("injected seam methods are captured as data without consulting Object.prototype", () => {
  const resolveDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "resolve");
  const connectDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "connectAndGet");
  Object.defineProperties(Object.prototype, {
    resolve: { configurable: true, value: async () => [] },
    connectAndGet: { configurable: true, value: async () => { throw new Error("unused"); } },
  });
  try {
    assert.throws(() => createGuardedFetcher({ resolver: {} as never }), /resolver is invalid/);
    assert.throws(() => createGuardedFetcher({ transport: {} as never }), /transport is invalid/);
  } finally {
    if (resolveDescriptor === undefined) delete (Object.prototype as Record<string, unknown>).resolve;
    else Object.defineProperty(Object.prototype, "resolve", resolveDescriptor);
    if (connectDescriptor === undefined) delete (Object.prototype as Record<string, unknown>).connectAndGet;
    else Object.defineProperty(Object.prototype, "connectAndGet", connectDescriptor);
  }

  let reads = 0;
  const resolver = {};
  Object.defineProperty(resolver, "resolve", {
    enumerable: true,
    get() { reads += 1; return async () => []; },
  });
  assert.throws(() => createGuardedFetcher({ resolver: resolver as never }));
  assert.equal(reads, 0);

  class ResolverClass {
    async resolve() { return [{ address: "192.0.2.1", family: 4 as const }]; }
    cancel() {}
  }
  assert.doesNotThrow(() => createGuardedFetcher({ resolver: new ResolverClass() }));
});

test("an omitted resolver cancel hook does not consult Object.prototype", async () => {
  let inheritedCalls = 0;
  const previous = Object.getOwnPropertyDescriptor(Object.prototype, "cancel");
  Object.defineProperty(Object.prototype, "cancel", {
    configurable: true,
    value() { inheritedCalls += 1; },
  });
  try {
    const fetcher = createGuardedFetcher({
      resolver: { async resolve() { throw new Error("lookup failed"); } },
    });
    await assert.rejects(
      () => fetcher.fetch("https://public.example/client"),
      (error: unknown) => hasReason(error, "dns_failed"),
    );
    assert.equal(inheritedCalls, 0);
  } finally {
    if (previous === undefined) delete (Object.prototype as Record<string, unknown>).cancel;
    else Object.defineProperty(Object.prototype, "cancel", previous);
  }
});

test("loopback helpers ignore option accessors without invoking them", () => {
  let getterCalls = 0;
  const opts = {} as { allowLoopback?: boolean };
  Object.defineProperty(opts, "allowLoopback", {
    enumerable: true,
    get() { getterCalls += 1; return true; },
  });
  assert.throws(
    () => admitCimdUrl("https://localhost/client", opts),
    (error: unknown) => hasReason(error, "url_admission_denied"),
  );
  assert.equal(isBlockedAddress("127.0.0.1", opts), true);
  assert.equal(getterCalls, 0);
});

test("response body protocol lookup ignores Object.prototype", async () => {
  let reads = 0;
  const previous = Object.getOwnPropertyDescriptor(Object.prototype, Symbol.asyncIterator);
  Object.defineProperty(Object.prototype, Symbol.asyncIterator, {
    configurable: true,
    get() {
      reads += 1;
      return async function* () { yield new TextEncoder().encode("{}"); };
    },
  });
  try {
    const fetcher = createGuardedFetcher({
      resolver: { resolve: async () => [{ address: "93.184.216.34", family: 4 }] },
      transport: { async connectAndGet(req) {
        return {
          status: 200, redirected: false,
          finalUrl: `https://${req.hostHeader}${req.requestTarget}`,
          headersDistinct: { "content-type": ["application/json"] },
          encodedBody: {} as AsyncIterable<Uint8Array>,
        };
      } },
    });
    await assert.rejects(
      () => fetcher.fetch("https://public.example/client"),
      (error: unknown) => hasReason(error, "fetch_failed"),
    );
    assert.equal(reads, 0);
  } finally {
    if (previous === undefined) delete (Object.prototype as Record<PropertyKey, unknown>)[Symbol.asyncIterator];
    else Object.defineProperty(Object.prototype, Symbol.asyncIterator, previous);
  }
});

test("injected transport response fields cannot come from a plain prototype", async () => {
  let reads = 0;
  const prototype = Object.create(null) as Record<string, unknown>;
  Object.defineProperty(prototype, "status", {
    get() { reads += 1; return 200; },
  });
  const response = Object.assign(Object.create(prototype), {
    redirected: false,
    finalUrl: "https://public.example/client",
    headersDistinct: { "content-type": ["application/json"] },
    encodedBody: (async function* () { yield new TextEncoder().encode("{}"); })(),
  });
  const fetcher = createGuardedFetcher({
    resolver: { resolve: async () => [{ address: "93.184.216.34", family: 4 }] },
    transport: { async connectAndGet() { return response; } },
  });
  await assert.rejects(
    () => fetcher.fetch("https://public.example/client"),
    (error: unknown) => hasReason(error, "status_not_200"),
  );
  assert.equal(reads, 0);
});

test("injected transport may return a class-based response", async () => {
  const clientId = "https://public.example/client";
  const payload = JSON.stringify({
    client_id: clientId, client_name: "Class response",
    redirect_uris: ["https://client.example/callback"],
  });
  class TransportResponse {
    get status() { return 200; }
    get redirected() { return false; }
    get finalUrl() { return clientId; }
    get headersDistinct() { return { "content-type": ["application/json"] }; }
    get encodedBody() {
      return (async function* () { yield new TextEncoder().encode(payload); })();
    }
  }
  const fetcher = createGuardedFetcher({
    resolver: { resolve: async () => [{ address: "93.184.216.34", family: 4 }] },
    transport: { async connectAndGet() { return new TransportResponse() as never; } },
  });
  assert.equal((await fetcher.fetch(clientId)).document.client_name, "Class response");
});

function hasReason(error: unknown, reason: string): boolean {
  return error instanceof Error && (error as { reason?: unknown }).reason === reason;
}
