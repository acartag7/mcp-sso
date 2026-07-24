// FROZEN acceptance suite — S6b AS metadata flag (docs/contracts.md §17.1 "When
// enabled, AS metadata emits client_id_metadata_document_supported: true" + §16;
// verification T1.S6b row S6b.7). THE PAIR: the flag appears ONLY when cimd is
// enabled and is ABSENT (not false) when disabled, while `none` stays
// UNCONDITIONAL in token_endpoint_auth_methods_supported. Pure black-box over the
// metadata builder. FAITHFULNESS: asserts only presence/absence of the pinned
// flag + the unconditional `none`; no other metadata shape is frozen.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";

const phases = JSON.parse(readFileSync(new URL("../phases.json", import.meta.url), "utf8"));

if (phases["s6b-cimd-flow"] !== true) {
  test("s6b-cimd-flow inactive — activate via test/acceptance/phases.json", { skip: true }, () => {});
} else {
  const CFG = "../../../src/config.ts";
  const { createBridgeConfig } = (await import(CFG)) as any;
  const META = "../../../src/metadata.ts";
  const { authorizationServerMetadata } = (await import(META)) as any;

  const KEY = "client_id_metadata_document_supported";
  function jwk(): any { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" }; }
  function cfg(cimd?: any): any {
    return createBridgeConfig({
      issuer: "https://auth.test", resource: "https://api.test/mcp",
      consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
      redirectAllowlist: ["https://client.test/cb"], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
      allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" }, cimd,
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });
  }

  test("cimd enabled ⇒ client_id_metadata_document_supported: true (and `none` stays advertised)", () => {
    const meta = authorizationServerMetadata(cfg({ enabled: true }));
    assert.equal(meta[KEY], true);
    assert.ok(Array.isArray(meta.token_endpoint_auth_methods_supported) && meta.token_endpoint_auth_methods_supported.includes("none"), "`none` stays advertised");
  });

  test("cimd absent ⇒ the flag is ABSENT (not false); `none` is unconditional", () => {
    const meta = authorizationServerMetadata(cfg(undefined));
    assert.ok(!(KEY in meta), "flag omitted entirely when disabled");
    assert.ok(meta.token_endpoint_auth_methods_supported.includes("none"), "`none` is unconditional");
  });

  // "Disabled" is represented by OMITTING the cimd block (config shape is
  // cimd?: { enabled: true }); the "cimd absent ⇒ flag absent" test above IS the
  // disabled case. { enabled: false } is not a valid config, so it is not asserted here.
}
