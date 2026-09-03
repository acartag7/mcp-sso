import assert from "node:assert/strict";
import { test } from "node:test";
import {
  authorizationOccurrences, headerString, headersFromDistinct, INVALID_RESOURCE, isMcpPath, noStoreHeaders, readHeader, resourceParam,
} from "../src/adapters/http.ts";

test("resourceParam omits valueless occurrences before enforcing the singleton resource policy", () => {
  assert.equal(resourceParam(undefined), undefined);
  assert.equal(resourceParam(""), undefined);
  assert.equal(resourceParam(["", ""]), undefined);
  assert.equal(resourceParam(["https://api.test/mcp", ""]), "https://api.test/mcp");
  assert.equal(resourceParam(["", "https://api.test/mcp"]), "https://api.test/mcp");
  assert.equal(resourceParam(["https://api.test/mcp", "https://other.test/mcp"]), INVALID_RESOURCE);
  assert.equal(resourceParam(["https://api.test/mcp", 7]), INVALID_RESOURCE);
});

test("headerString rejects normalized arrays and case-duplicate keys", () => {
  assert.equal(headerString({ Origin: "https://auth.test" }, "origin"), "https://auth.test");
  assert.equal(headerString({}, "origin"), undefined);
  for (const origin of [
    ["https://auth.test"],
    ["https://auth.test", "https://evil.test"],
    ["https://evil.test", "https://auth.test"],
  ]) {
    assert.equal(headerString({ Origin: origin }, "origin"), undefined);
  }
  assert.equal(headerString({ Origin: "https://auth.test", origin: "https://evil.test" }, "origin"), undefined);
  assert.equal(headerString({ origin: "https://evil.test", Origin: "https://auth.test" }, "origin"), undefined);
  assert.deepEqual(readHeader({ Origin: ["https://auth.test"] }, "origin"), { ambiguous: true });
});

test("headersFromDistinct preserves multiplicity while joining repeated Cookie fields", () => {
  const headers = headersFromDistinct({
    authorization: ["Bearer attacker", "Basic credentials"],
    origin: ["https://auth.test"],
    cookie: ["a=1", "b=2"],
  });
  assert.deepEqual(headers.authorization, ["Bearer attacker", "Basic credentials"]);
  assert.equal(headers.origin, "https://auth.test");
  assert.equal(headers.cookie, "a=1; b=2");
  assert.equal(headerString(headers, "authorization"), undefined);
  assert.equal(headerString(headers, "cookie"), "a=1; b=2");
});

test("headersFromDistinct keeps injector fallback arrays and case variants ambiguous", () => {
  const headers = headersFromDistinct(undefined, {
    Authorization: "Bearer attacker",
    authorization: "Basic credentials",
    origin: ["https://auth.test"],
    cookie: ["a=1", "b=2"],
  });
  assert.equal(headerString(headers, "authorization"), undefined);
  assert.equal(headerString(headers, "origin"), undefined);
  assert.equal(headerString(headers, "cookie"), "a=1; b=2");
  assert.throws(() => headersFromDistinct(undefined), /occurrence metadata is unavailable/);
});

test("headerString rejects comma-coalesced non-Cookie security headers", () => {
  assert.equal(headerString({ authorization: "Bearer attacker, Basic credentials" }, "authorization"), undefined);
  assert.equal(headerString({ origin: "https://auth.test, https://evil.test" }, "origin"), undefined);
  assert.equal(headerString({ cookie: "a=1,still-one-cookie-string" }, "cookie"), "a=1,still-one-cookie-string");
});

test("noStoreHeaders preserves existing response headers without mutating the input", () => {
  const original = { location: "https://client.test/callback", "set-cookie": "flow=value; Path=/" };
  const headers = noStoreHeaders(original);
  assert.deepEqual(headers, { ...original, "cache-control": "no-store" });
  assert.deepEqual(original, { location: "https://client.test/callback", "set-cookie": "flow=value; Path=/" });
});

// isMcpPath centralizes the /mcp request-target check the examples' Origin gate
// (and the gateway's JSON body parser) share. The property that matters: it must
// hold for an ABSOLUTE-FORM request-target (`POST http://host/mcp`), which a raw
// `request.url === "/mcp"` / `.split("?")[0]` check misses — that gap let an
// absolute-form target skip the fastify-sqlite Origin gate (the #4 finding).

test("isMcpPath: origin-form /mcp targets are recognized", () => {
  assert.equal(isMcpPath("/mcp"), true);
  assert.equal(isMcpPath("/mcp?foo=bar"), true); // query is stripped by the pathname parse
});

test("isMcpPath: absolute-form request-targets are recognized (the raw string-check gap)", () => {
  // A client/proxy may send `POST http://host/mcp`; request.url is then the full
  // URL, which a raw `.split(\"?\")[0] === \"/mcp\"` check misses (bypassing the
  // Origin gate). The pathname parse must catch it.
  assert.equal(isMcpPath("http://attacker.invalid/mcp"), true);
  assert.equal(isMcpPath("https://api.example.com/mcp"), true);
  assert.equal(isMcpPath("http://attacker.invalid/mcp?x=1"), true);
});

test("isMcpPath: non-/mcp targets and garbage return false without throwing", () => {
  assert.equal(isMcpPath("/oauth/authorize"), false);
  assert.equal(isMcpPath("/mcp/tools"), false); // a subpath is not /mcp
  assert.equal(isMcpPath("/"), false);
  assert.equal(isMcpPath("not a url at all"), false);
  assert.equal(isMcpPath(""), false);
});

// §8.4 raw-occurrence boundary: one occurrence as a one-element array, absence
// as undefined, case-duplicated normalized keys preserving BOTH values so the
// verifier's more-than-one rule fails closed instead of one credential
// silently winning, and array values flattened into the occurrence list.
test("authorizationOccurrences keeps the raw occurrence shape at every source", () => {
  assert.deepEqual(authorizationOccurrences({ authorization: ["Bearer one"] }), ["Bearer one"]);
  assert.deepEqual(authorizationOccurrences({ authorization: ["Bearer one", "Bearer two"] }), ["Bearer one", "Bearer two"]);
  assert.equal(authorizationOccurrences({}), undefined);
  assert.equal(authorizationOccurrences(undefined, {}), undefined);
  assert.deepEqual(authorizationOccurrences(undefined, { authorization: "Bearer one" }), ["Bearer one"]);
  assert.deepEqual(authorizationOccurrences(undefined, { authorization: ["Bearer one", "Bearer two"] }), ["Bearer one", "Bearer two"]);
});

test("authorizationOccurrences fails closed on case-duplicated normalized keys", () => {
  assert.deepEqual(
    authorizationOccurrences(undefined, { Authorization: "Bearer attacker", authorization: "Bearer valid" }),
    ["Bearer attacker", "Bearer valid"],
    "both occurrences survive, so the verifier's more-than-one rule rejects the request",
  );
  const typed = authorizationOccurrences as (d: undefined, n: Record<string, unknown>) => string[] | undefined;
  assert.deepEqual(
    typed(undefined, { AUTHORIZATION: "Bearer a", Authorization: "Bearer b", authorization: ["Bearer c"] }),
    ["Bearer a", "Bearer b", "Bearer c"],
    "every case variant and array entry joins the occurrence list",
  );
  assert.deepEqual(authorizationOccurrences({ authorization: ["Bearer distinct"] }, { Authorization: "Bearer ignored" }),
    ["Bearer distinct"], "a present distinct source is authoritative");
});

test("authorizationOccurrences rejects a malformed duplicate instead of dropping it", () => {
  const typed = authorizationOccurrences as (d: undefined, n: Record<string, unknown>) => string[] | undefined;
  assert.throws(() => typed(undefined, { Authorization: 7, authorization: "Bearer valid" }),
    /normalized Authorization occurrence is not a string/,
    "a non-string case-variant duplicate must not be silently dropped to leave the valid credential a singleton");
  assert.throws(() => typed(undefined, { authorization: ["Bearer valid", 7] }),
    /normalized Authorization occurrence is not a string/);
  assert.deepEqual(typed(undefined, { "content-type": 7, authorization: "Bearer valid" }), ["Bearer valid"],
    "malformed values under other keys are none of this boundary's business");
});

test("authorizationOccurrences gives the distinct source the same case and type closure", () => {
  const distinctTyped = authorizationOccurrences as (d: Record<string, unknown>, n?: undefined) => string[] | undefined;
  assert.deepEqual(
    distinctTyped({ Authorization: ["Bearer attacker"], authorization: ["Bearer valid"] }),
    ["Bearer attacker", "Bearer valid"],
    "hand-built case-variant distinct keys merge, so more-than-one rejects",
  );
  assert.throws(() => distinctTyped({ authorization: [7, "Bearer valid"] }),
    /distinct Authorization occurrence is not a string/);
  assert.throws(() => distinctTyped({ authorization: [new String("Bearer valid")] }),
    /distinct Authorization occurrence is not a string/,
    "a boxed String is an object, not a primitive string, and is rejected rather than trimmed into a token");
  assert.equal(authorizationOccurrences({ authorization: [] }), undefined,
    "an empty occurrence list is absence, which still fails closed at the verifier");
});

test("authorizationOccurrences rejects a malformed matching container, not just its elements", () => {
  const distinctTyped = authorizationOccurrences as (d: Record<string, unknown>) => string[] | undefined;
  assert.throws(() => distinctTyped({ Authorization: "", authorization: ["Bearer valid"] }),
    /distinct Authorization occurrence is not a string/,
    "a non-array matching value must throw even when its length is 0, never skip to the valid case variant");
});

test("authorizationOccurrences reads each element once and publishes the snapshot", () => {
  let reads = 0;
  const hostile = new Proxy(["Bearer valid"], {
    get(target, prop, receiver) {
      if (prop === "0") {
        reads += 1;
        return reads === 1 ? "Bearer valid" : new String("Bearer poisoned");
      }
      return Reflect.get(target, prop, receiver);
    },
  }) as unknown as string[];
  assert.deepEqual(authorizationOccurrences({ authorization: hostile }), ["Bearer valid"],
    "the validated snapshot is what is published; the second, poisoned read never happens");
  assert.equal(reads, 1, "each element is read exactly once");
  const readsNormalized = { count: 0, map: {} as Record<string, string[]> };
  readsNormalized.map.authorization = new Proxy(["Bearer valid"], {
    get(target, prop, receiver) {
      if (prop === "0") { readsNormalized.count += 1; return readsNormalized.count === 1 ? "Bearer valid" : "poisoned"; }
      return Reflect.get(target, prop, receiver);
    },
  }) as unknown as string[];
  assert.deepEqual(authorizationOccurrences(undefined, readsNormalized.map), ["Bearer valid"]);
  assert.equal(readsNormalized.count, 1, "the normalized branch reads each element once too");
});
