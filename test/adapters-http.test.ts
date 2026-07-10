import assert from "node:assert/strict";
import { test } from "node:test";
import { isMcpPath } from "../src/adapters/http.ts";

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
