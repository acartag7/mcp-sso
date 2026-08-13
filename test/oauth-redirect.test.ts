import assert from "node:assert/strict";
import { test } from "node:test";
import type { ClientRegistration } from "../src/ports/client-store.ts";
import {
  DEFAULT_ALLOWED_REDIRECT_ORIGINS,
  assertAllowedRedirectUri,
  assertRedirectAllowedForClient,
} from "../src/redirect.ts";
import { OAuthError } from "../src/errors.ts";

function allow(uri: string, list: string[] = []): { ok: true; value: string } | { ok: false; code: string } {
  try {
    return { ok: true, value: assertAllowedRedirectUri(uri, list) };
  } catch (e) {
    return { ok: false, code: e instanceof OAuthError ? e.code : "throw" };
  }
}

test("DEFAULT_ALLOWED_REDIRECT_ORIGINS covers hosted clients only", () => {
  assert.deepEqual([...DEFAULT_ALLOWED_REDIRECT_ORIGINS], [
    "https://claude.ai", "https://chatgpt.com",
  ]);
});

test("defaults: web MCP-client origins accepted on any callback path", () => {
  assert.equal(allow("https://chatgpt.com/connector_platform_oauth_abc-123").ok, true);
  assert.equal(allow("https://claude.ai/api/mcp/auth/callback").ok, true);
});

test("an operator allowlisting only a hosted client does not trust loopback", () => {
  const hostedOnly = ["https://claude.ai/callback"];
  assert.equal(allow("https://claude.ai/callback", hostedOnly).ok, true);
  assert.equal(allow("http://127.0.0.1:9/callback", hostedOnly).ok, false);
  assert.equal(allow("http://localhost:9/callback", hostedOnly).ok, false);
});

test("loopback is denied by default and enabled explicitly with RFC 8252 any-port matching", () => {
  for (const port of [29352, 40128, 8080, 1, 65535]) {
    assert.equal(allow(`http://localhost:${port}/callback`).ok, false, `localhost:${port} implicit`);
    assert.equal(allow(`http://127.0.0.1:${port}/callback`).ok, false, `127.0.0.1:${port} implicit`);
    assert.equal(allow(`http://localhost:${port}/callback`, ["http://localhost"]).ok, true, `localhost:${port} explicit`);
    assert.equal(allow(`http://127.0.0.1:${port}/callback`, ["http://127.0.0.1"]).ok, true, `127.0.0.1:${port} explicit`);
  }
});

test("an explicit-port loopback entry is NOT widened to any port", () => {
  assert.equal(allow("http://[::1]:9999/cb", ["http://[::1]:80"]).ok, false);
  assert.equal(allow("http://localhost:9999/cb", ["http://localhost"]).ok, true);
  assert.equal(allow("http://[::1]:9999/cb", ["http://[::1]"]).ok, true);
});

test("allowlist adds origins without implicitly adding loopback", () => {
  assert.equal(allow("https://my-app.com/oauth/callback", ["https://my-app.com"]).ok, true);
  assert.equal(allow("https://chatgpt.com/x", ["https://my-app.com"]).ok, true);
  assert.equal(allow("http://localhost:9999/cb", ["https://my-app.com"]).ok, false);
});

test("security: disallowed origins, lookalikes, wildcard, userinfo rejected", () => {
  assert.equal(allow("https://evil.com/callback").ok, false);
  assert.equal(allow("https://chatgpt.com.evil.com/cb").ok, false); // lookalike host
  assert.equal(allow("https://evil.com/cb", ["*"]).ok, false); // "*" is NOT allow-all
  assert.equal(allow("https://user:pass@chatgpt.com/cb").ok, false); // userinfo
  assert.equal(allow("https://localhost:443/cb").ok, false); // https loopback not matched by http default
});

test("a path-specific loopback entry is NOT widened to any port", () => {
  assert.equal(allow("http://[::1]:9999/other", ["http://[::1]/callback"]).ok, false);
  assert.equal(allow("http://[::1]:9999/any", ["http://[::1]/?cb=foo"]).ok, false);
  assert.equal(allow("http://[::1]:9999/any", ["http://[::1]"]).ok, true); // origin entry widens
});

test("a path-specific localhost entry stays restricted", () => {
  assert.equal(allow("http://localhost:7/cb", ["http://localhost/exact"]).ok, false);
});

test("IPv6 loopback ([::1]) matches any port when allowlisted as an origin", () => {
  assert.equal(allow("http://[::1]:49152/callback", ["http://[::1]"]).ok, true);
  assert.equal(allow("http://[::1]:8/cb").ok, false); // not a default
});

test("exact-match entry works and returns the normalized URI", () => {
  const r = allow("https://my-app.com/exact-cb", ["https://my-app.com/exact-cb"]);
  assert.equal(r.ok, true);
  assert.equal(r.ok && r.value, "https://my-app.com/exact-cb");
});

// --- per-client policy (stored-DCR mode, RC item b) ---

function client(applicationType: "native" | "web", redirectUris: string[]): ClientRegistration {
  return { clientId: "c", redirectUris, applicationType, issuedAtEpoch: 0 };
}

function allowClient(uri: string, c: ClientRegistration): { ok: true; value: string } | { ok: false; code: string } {
  try {
    return { ok: true, value: assertRedirectAllowedForClient(uri, c) };
  } catch (e) {
    return { ok: false, code: e instanceof OAuthError ? e.code : "throw" };
  }
}

test("web client: https exact match only", () => {
  const c = client("web", ["https://app.example.com/cb"]);
  assert.equal(allowClient("https://app.example.com/cb", c).ok, true);
  assert.equal(allowClient("https://app.example.com/other", c).ok, false); // path mismatch
  assert.equal(allowClient("http://app.example.com/cb", c).ok, false); // not https
  assert.equal(allowClient("https://evil.test/cb", c).ok, false); // not registered
  assert.equal(allowClient("https://user:pass@app.example.com/cb", c).ok, false); // userinfo
});

test("native client: loopback any port matches a registered loopback URI", () => {
  const c = client("native", ["http://localhost/callback"]);
  assert.equal(allowClient("http://localhost:8080/callback", c).ok, true); // any port (RFC 8252)
  assert.equal(allowClient("http://localhost/callback", c).ok, true); // exact
  assert.equal(allowClient("http://localhost:9000/other", c).ok, false); // path mismatch
  assert.equal(allowClient("https://localhost/callback", c).ok, false); // scheme mismatch
  assert.equal(allowClient("http://evil.test/callback", c).ok, false); // not loopback
});
