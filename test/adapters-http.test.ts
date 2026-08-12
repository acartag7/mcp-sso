import assert from "node:assert/strict";
import { test } from "node:test";
import { headerString, headersFromDistinct, isMcpPath, noStoreHeaders, readHeader } from "../src/adapters/http.ts";

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
