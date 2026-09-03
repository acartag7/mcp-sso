import assert from "node:assert/strict";
import { test } from "node:test";
import {
  headerString, headersFromDistinct, INVALID_RESOURCE, isMcpPath, noStoreHeaders, readHeader, resourceParam,
} from "../src/adapters/http.ts";
import { authorizationOccurrences } from "../src/adapters/authorization-occurrences.ts";

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

test("authorizationOccurrences rejects accessor-backed elements outright", () => {
  // The static-data boundary: an index accessor's getter runs attacker code
  // during enumeration (it could delete a sibling occurrence before the
  // snapshot reaches it), so accessors throw instead of being single-read.
  const hostile = ["placeholder"] as string[];
  let reads = 0;
  Object.defineProperty(hostile, "0", {
    enumerable: true, configurable: true,
    get() { reads += 1; delete hostile[1]; return "Bearer attacker"; },
  });
  hostile[1] = "Bearer victim";
  assert.throws(() => authorizationOccurrences({ authorization: hostile }),
    /has an accessor property/,
    "a getter that erases a sibling occurrence is rejected before any read");
  assert.equal(reads, 0, "the accessor is never invoked");
});

test("authorizationOccurrences ignores a lying length without trusting a Proxy", () => {
  // A non-Proxy subclass with a lying length getter keeps honest own keys, so
  // its present elements still publish and emptiness comes from the snapshot.
  class LyingLength extends Array<string> { override get length(): number { return 0; } }
  const lying = new LyingLength() as unknown as string[];
  lying.push("Bearer attacker");
  assert.deepEqual(
    authorizationOccurrences({ Authorization: lying, authorization: ["Bearer valid"] }),
    ["Bearer attacker", "Bearer valid"],
    "the faked-empty variant still contributes, so more-than-one rejects",
  );
  assert.deepEqual(authorizationOccurrences({ authorization: lying }), ["Bearer attacker"],
    "a sole lying-length array publishes its real snapshot, not its claimed emptiness");
});

test("authorizationOccurrences pins the remaining contract class: sparse holes and blanks", () => {
  const sparse = authorizationOccurrences as (d: Record<string, unknown>) => string[] | undefined;
  assert.deepEqual(sparse({ authorization: [, "Bearer valid"] }), ["Bearer valid"],
    "a sparse hole is an absent element: it contributes nothing and never hides a present one");
  assert.deepEqual(sparse({ authorization: ["Bearer valid", ,] }), ["Bearer valid"]);
  assert.deepEqual(authorizationOccurrences({ authorization: [""] }), [""],
    "a blank occurrence passes through and fails closed at the verifier's bearer grammar");
  assert.deepEqual(authorizationOccurrences(undefined, { authorization: "" }), [""],
    "the normalized branch passes blanks through too");
});

test("authorizationOccurrences rejects a Proxy that could hide occurrences", () => {
  const hiding = new Proxy(["Bearer attacker", "Bearer valid"], {
    ownKeys(target) { return Reflect.ownKeys(target).filter((key) => key !== "0"); },
  }) as unknown as string[];
  assert.throws(() => authorizationOccurrences({ authorization: hiding }),
    /is not a plain object/,
    "no enumeration of a Proxy is evidence; a hidden index must not publish a singleton");
  const hidingSource = new Proxy({ Authorization: ["Bearer attacker"], authorization: ["Bearer valid"] }, {
    ownKeys(target) { return ["Authorization"]; },
  }) as unknown as Record<string, string[]>;
  assert.throws(() => authorizationOccurrences(hidingSource),
    /Authorization source is not a plain object/,
    "a Proxy source hiding a case-variant key is rejected before enumeration");
});

test("authorizationOccurrences counts non-enumerable array elements as occurrences", () => {
  const hostile = ["Bearer attacker", "Bearer valid"] as string[];
  Object.defineProperty(hostile, "0", { enumerable: false, value: "Bearer attacker" });
  assert.deepEqual(authorizationOccurrences({ authorization: hostile }), ["Bearer attacker", "Bearer valid"],
    "a non-enumerable own index must not silently vanish from the occurrence list");
  const sourceOnly = { Authorization: ["Bearer attacker"] } as Record<string, string[]>;
  Object.defineProperty(sourceOnly, "authorization", { enumerable: false, value: ["Bearer valid"] });
  assert.deepEqual(authorizationOccurrences(sourceOnly), ["Bearer attacker"],
    "a non-enumerable source key is not part of the header map, matching Object.entries semantics");
});

test("authorizationOccurrences rejects a present undefined under a matching key", () => {
  const distinct = { Authorization: undefined, authorization: ["Bearer valid"] } as unknown as Record<string, string[]>;
  assert.throws(() => authorizationOccurrences(distinct),
    /distinct Authorization occurrence is not a string/,
    "a case-variant junk entry must not silently drop the real occurrence");
  const normalized = { Authorization: undefined, authorization: "Bearer valid" } as unknown as Record<string, string>;
  assert.throws(() => authorizationOccurrences(undefined, normalized),
    /normalized Authorization occurrence is not a string/,
    "both source branches treat present-undefined as malformed, not absent");
});
