// FROZEN acceptance suite — S6a CIMD document validation + redirect-uri hygiene
// primitives (docs/contracts.md §17.1.3 + §17.1.5 F rules 18/19/20). Black-box.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const phases = JSON.parse(readFileSync(new URL("../phases.json", import.meta.url), "utf8"));

if (phases["s6a-cimd-primitives"] !== true) {
  test("s6a-cimd-primitives inactive — activate via test/acceptance/phases.json", { skip: true }, () => {});
} else {
  // Non-literal specifier keeps typecheck green while src/cimd is absent.
  const DOCUMENT = "../../../src/cimd/document.ts";
  const { validateCimdDocument, assertCimdRedirectUri } = (await import(DOCUMENT)) as any;

  const ID = "https://cdn.example.com/client";
  const base = (over: any = {}) => ({
    client_id: ID,
    client_name: "Example",
    redirect_uris: ["https://app.example.com/cb"],
    ...over,
  });
  const validate = (obj: any, id: any = ID) => validateCimdDocument(JSON.stringify(obj), id);
  const invalid = (obj: any, id: any = ID) =>
    assert.throws(
      () => validate(obj, id),
      (e: any) => e && e.reason === "document_invalid",
      "expected CimdError reason=document_invalid",
    );
  const invalidRaw = (raw: any, id: any = ID) =>
    assert.throws(
      () => validateCimdDocument(raw, id),
      (e: any) => e && e.reason === "document_invalid",
      "expected CimdError reason=document_invalid",
    );

  test("valid document returns a typed CimdDocument", () => {
    const d = validate(base());
    assert.equal(d.client_id, ID);
    assert.equal(d.client_name, "Example");
    assert.deepEqual(d.redirect_uris, ["https://app.example.com/cb"]);
  });

  test("client_id must equal raw EXACTLY (explicit :443 and case-folded host reject)", () => {
    invalid(base({ client_id: "https://cdn.example.com:443/client" }));
    invalid(base({ client_id: "https://CDN.example.com/client" }));
    invalid(base({ client_id: "https://cdn.example.com/client/" })); // trailing slash
    invalid(base({ client_id: "https://cdn.example.com/CLIENT" }));
  });

  test("required members absent reject", () => {
    invalid(base({ client_id: undefined }));
    invalid(base({ client_name: undefined }));
    invalid(base({ redirect_uris: undefined }));
  });

  test("wrong member JSON types reject (never coerced)", () => {
    invalid(base({ client_id: 123 }));
    invalid(base({ client_name: 123 }));
    invalid(base({ client_name: null }));
    invalid(base({ redirect_uris: "https://app.example.com/cb" }));
    invalid(base({ redirect_uris: { 0: "https://app.example.com/cb" } }));
  });

  test("client_name: non-empty and <= 256 chars", () => {
    invalid(base({ client_name: "" }));
    invalid(base({ client_name: "a".repeat(257) }));
    assert.equal(validate(base({ client_name: "a".repeat(256) })).client_name.length, 256);
  });

  test("redirect_uris cardinality is 1..16", () => {
    invalid(base({ redirect_uris: [] }));
    invalid(base({ redirect_uris: Array.from({ length: 17 }, (_, i) => `https://app.example.com/cb${i}`) }));
    assert.equal(
      validate(base({ redirect_uris: Array.from({ length: 16 }, (_, i) => `https://app.example.com/cb${i}`) })).redirect_uris.length,
      16,
    );
  });

  test("root must be a non-null, non-array JSON object", () => {
    for (const raw of ["[]", '"x"', "42", "null", "true", "[{}]"]) invalidRaw(raw);
  });

  test("malformed JSON rejects", () => {
    for (const raw of ["{not json", "", '{"client_id":', "undefined"]) invalidRaw(raw);
  });

  test("token_endpoint_auth_method: absent or \"none\" only", () => {
    assert.ok(validate(base())); // absent
    assert.ok(validate(base({ token_endpoint_auth_method: "none" })));
    invalid(base({ token_endpoint_auth_method: "client_secret_basic" }));
    invalid(base({ token_endpoint_auth_method: "private_key_jwt" }));
    invalid(base({ token_endpoint_auth_method: "" }));
  });

  test("client_secret / client_secret_expires_at reject", () => {
    invalid(base({ client_secret: "s3cr3t" }));
    invalid(base({ client_secret_expires_at: 0 }));
  });

  test("jwks: any private/symmetric param rejects; public-only + absent accepted", () => {
    for (const p of ["d", "p", "q", "dp", "dq", "qi", "oth", "k"])
      invalid(base({ jwks: { keys: [{ kty: "RSA", n: "abc", e: "AQAB", [p]: "x" }] } }));
    assert.ok(validate(base({ jwks: { keys: [{ kty: "RSA", n: "abc", e: "AQAB" }] } })));
    assert.ok(validate(base())); // jwks absent
  });

  test("malformed jwks rejects (not object / keys not array / non-object key / keys absent)", () => {
    invalid(base({ jwks: "nope" }));
    invalid(base({ jwks: { keys: "nope" } }));
    invalid(base({ jwks: { keys: ["nope"] } }));
    invalid(base({ jwks: {} }));
  });

  test("response_types must include \"code\" if present", () => {
    assert.ok(validate(base({ response_types: ["code"] })));
    assert.ok(validate(base({ response_types: ["code", "id_token"] })));
    invalid(base({ response_types: ["token"] }));
    invalid(base({ response_types: [] }));
  });

  test("grant_types must be a subset of {authorization_code, refresh_token} if present", () => {
    assert.ok(validate(base({ grant_types: ["authorization_code"] })));
    assert.ok(validate(base({ grant_types: ["authorization_code", "refresh_token"] })));
    invalid(base({ grant_types: ["client_credentials"] }));
    invalid(base({ grant_types: ["implicit"] }));
    invalid(base({ grant_types: ["authorization_code", "client_credentials"] })); // valid first, invalid later
  });

  test("neither response_types nor grant_types present is valid; unknown members ignored", () => {
    assert.ok(validate(base()));
    assert.ok(validate(base({ logo_uri: "https://x/y.png", jwks_uri: "https://x/jwks", foo: "bar" })));
  });

  test("redirect_uris hygiene: reject fragment / userinfo / http-non-loopback / wildcard / bad type", () => {
    invalid(base({ redirect_uris: ["https://app.example.com/cb#frag"] }));
    invalid(base({ redirect_uris: ["https://user@app.example.com/cb"] }));
    invalid(base({ redirect_uris: ["http://192.168.0.10/cb"] }));
    invalid(base({ redirect_uris: ["http://example.com/cb"] }));
    invalid(base({ redirect_uris: ["https://*.example.com/cb"] }));
    invalid(base({ redirect_uris: ["ftp://app.example.com/cb"] }));
    invalid(base({ redirect_uris: [123] }));
  });

  test("redirect_uris accepts https + loopback-http forms", () => {
    assert.ok(validate(base({
      redirect_uris: ["https://app.example.com/cb", "http://127.0.0.1:49152/cb", "http://localhost/cb", "http://[::1]/cb"],
    })));
  });

  // --- assertCimdRedirectUri (pure per-URI hygiene predicate; throws document_invalid) ---
  const uriOk = (u: any) => assert.doesNotThrow(() => assertCimdRedirectUri(u), `${u} should be accepted`);
  const uriBad = (u: any) =>
    assert.throws(() => assertCimdRedirectUri(u), (e: any) => e && e.reason === "document_invalid", `${u} should be rejected`);

  test("assertCimdRedirectUri accepts https + loopback-http (localhost/127.0.0.1/[::1])", () => {
    uriOk("https://app.example.com/cb");
    uriOk("https://app.example.com:8443/cb");
    uriOk("http://127.0.0.1:49152/cb");
    uriOk("http://localhost/cb");
    uriOk("http://[::1]/cb");
  });

  test("assertCimdRedirectUri rejects the full edge class", () => {
    uriBad("http://192.168.0.10/cb"); // http non-loopback
    uriBad("http://example.com/cb");
    uriBad("http://10.0.0.1/cb");
    uriBad("http://127.0.0.2/cb"); // 127/8 but not exactly 127.0.0.1 (rule 20 is exact-host)
    uriBad("http://0177.0.0.1/cb"); // octal normalizes to 127.0.0.1; raw != canonical
    uriBad("http://2130706433/cb"); // dword normalizes to 127.0.0.1
    uriBad("http://[0:0:0:0:0:0:0:1]/cb"); // expanded ::1 form
    uriBad("https://app.example.com/cb#x"); // fragment
    uriBad("https://app.example.com/cb#"); // trailing #
    uriBad("https://user@app.example.com/cb"); // userinfo
    uriBad("https://@app.example.com/cb"); // empty userinfo
    uriBad("https://*.example.com/cb"); // wildcard host
    uriBad("ftp://app.example.com/cb"); // wrong scheme
    uriBad("app.example.com/cb"); // no scheme
    uriBad(""); // empty
    uriBad("https://app.example.com/c\\b"); // backslash
    uriBad("https://app.example.com/c%zz"); // malformed percent
    uriBad("https://app.example.com/c\u0001"); // C0 control
  });

  test("assertCimdRedirectUri rejects non-string arguments", () => {
    for (const v of [123, null, undefined, {}, []]) uriBad(v);
  });

  test("redirect_uris validates EVERY entry, not just index 0", () => {
    invalid(base({ redirect_uris: ["https://good.example/cb", "https://evil.example/cb#frag"] }));
    invalid(base({ redirect_uris: ["https://good.example/cb", "http://192.168.0.10/cb"] }));
    invalid(base({ redirect_uris: ["https://good.example/cb", 123] }));
  });

  test("response_types / grant_types must be ARRAYS (a string is not coerced)", () => {
    invalid(base({ response_types: "code" }));   // "codex".includes("code")===true trap
    invalid(base({ response_types: "codex" }));
    invalid(base({ grant_types: "authorization_code" }));
  });

  test("jwks keys entries must be plain objects (null / array reject, no crash)", () => {
    invalid(base({ jwks: { keys: [null] } }));
    invalid(base({ jwks: { keys: [[]] } }));
    invalid(base({ jwks: { keys: [{ kty: "RSA", n: "a", e: "AQAB" }, null] } }));
  });
}
