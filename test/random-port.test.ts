import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { decodeJwt, type JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import type { NormRequest } from "../src/adapters/http.ts";
import { createUpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import { createBridgeConfig } from "../src/config.ts";
import {
  generateAuthorizationCode, generateConsentJti, generateRefreshFamilyId, generateRefreshToken, pkceChallenge,
} from "../src/crypto.ts";
import { randomBytesFrom } from "../src/ports/random.ts";
import { noopAudit } from "../src/ports/audit.ts";
import { SeededRandom } from "./parity/random.ts";
import { FixtureStore } from "./parity/store.ts";

const VECTOR = "dda46198e668964d43f395ded2b195190c4faafebf113b2fd50ad2b0e30f42c05b202c7f0d3757bed3151fded3028ef32fa052b4bfcfbaab4ac4691461281731254a28fd11d29da17b20af3dbbdf3f8804e5003114e9f198d925a4cf23fa9f4a";

test("fixture PRNG matches the section 19 derivation and preserves unused block suffixes", () => {
  const whole = Buffer.from(new SeededRandom("fixture-seed").bytes(96)).toString("hex");
  const split = new SeededRandom("fixture-seed");
  const segmented = Buffer.concat([
    Buffer.from(split.bytes(7)), Buffer.from(split.bytes(25)), Buffer.from(split.bytes(64)),
  ]).toString("hex");
  assert.equal(whole, VECTOR); assert.equal(segmented, VECTOR);
});

test("fixture PRNG rejects invalid byte counts and malformed seeds", () => {
  const random = new SeededRandom("seed");
  for (const length of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => random.bytes(length), /positive safe integer/);
  }
  assert.throws(() => new SeededRandom(""), /non-empty/);
  assert.throws(() => new SeededRandom("\ud800"), /well-formed/);
  assert.throws(() => new SeededRandom("a".repeat(1_025)), /1024/);
});

test("generated OAuth values consume one shared fixture stream", () => {
  const random = new SeededRandom("fixture-seed");
  assert.equal(generateAuthorizationCode(random), "ac_3aRhmOZolk1D85Xe0rGVGQxPqv6_ETsv1QrSsOMPQsA");
  const family = generateRefreshFamilyId(random);
  assert.equal(family, "WyAsfw03V77TFR_e0wKO8y-g");
  assert.equal(generateConsentJti(random), "UrS_z7qrSsRpFGEoFzElSij9");
  assert.equal(generateRefreshToken(family, random), "rt.WyAsfw03V77TFR_e0wKO8y-g.EdKdoXsgrz273z-IBOUAMRTp8ZjZJaTPI_qfSniFaLw");
});

test("generated values reject a RandomPort result with the wrong shape or length", () => {
  assert.throws(() => randomBytesFrom({ bytes: () => new Uint8Array(3) }, 4), /wrong byte count/);
  assert.throws(() => randomBytesFrom({ bytes: () => "four" as unknown as Uint8Array }, 4), /wrong byte count/);
});

test("one injected stream spans store, Bridge grants, and the upstream authorize leg", async () => {
  const random = new SeededRandom("bridge-seed");
  const store = new FixtureStore({}, random);
  try {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const config = createBridgeConfig({
      issuer: "https://auth.example.com", resource: "https://api.example.com/mcp",
      consentSigningSecret: "fixture-consent-signing-secret-32-bytes", signingPrivateJwk: {
        ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "fixture-signing-key",
      } as JWK, signingKeyId: "fixture-signing-key",
      redirectAllowlist: ["https://client.example.com/callback"], scopeCatalog: ["mcp:read"],
      defaultScopes: ["mcp:read"], allowedOrigins: ["https://auth.example.com"],
      dcr: { mode: "stored", store }, accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
      consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });
    const clock = { nowMs: () => Date.parse("2026-08-31T10:00:00.000Z") };
    const rateLimit = { check: async () => true };
    const bridge = new Bridge({ config, store, clock, audit: noopAudit, rateLimit, random });
    const registered = await bridge.handleRegister(request({}, { redirect_uris: ["https://client.example.com/callback"] }));
    const clientId = (registered.body as { client_id: string }).client_id;
    assert.equal(store.snapshot().store_instance[0]?.instance_id, "Ky-YDhJu9WPkFFtASWZ6QhLg");
    assert.equal(clientId, "mcpdc_dbbda35787b74054a4dfbc49002757c2");
    const verifier = "fixture-verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
    const consent = await bridge.handleAuthorize(request({ response_type: "code", client_id: clientId,
      redirect_uri: "https://client.example.com/callback", code_challenge: pkceChallenge(verifier),
      code_challenge_method: "S256", scope: "mcp:read", state: "fixture-state" }), { subject: "subject-fixture" });
    const consentToken = /name="consent_token" value="([^"]+)"/u.exec(String(consent.body))?.[1];
    assert.ok(consentToken); assert.equal(decodeJwt(consentToken).jti, "pInhNt29vUiC_sT8h07GB3ai");
    const approved = await bridge.handleApprove(request({}, { consent_token: consentToken, approved: "true" }, {
      origin: "https://auth.example.com",
    }));
    const code = new URL(String(approved.headers.location)).searchParams.get("code");
    assert.equal(code, "ac_Q_X8LzjIRqXSK_U2Fb6EWE83oh0l1QlxVEfa9MPQ3h4");
    const tokens = await bridge.handleToken(request({}, { grant_type: "authorization_code", code,
      redirect_uri: "https://client.example.com/callback", client_id: clientId, code_verifier: verifier }));
    assert.equal((tokens.body as { refresh_token: string }).refresh_token,
      "rt.3uBzXggOdEZuqbw4w_bncBjk.LMmwyKTkWuYVWdTztSKkCj4_3J_qU5o3RzhdEn5NzNk");
    const upstream = createUpstreamRedirectFlow({ bridge, store, clock, audit: noopAudit, rateLimit, random,
      identity: { redirectUri: "https://auth.example.com/oauth/callback",
        buildAuthorizationUrl: ({ state, nonce, codeChallenge }) => `https://idp.example.com/authorize?${new URLSearchParams({ state, nonce, code_challenge: codeChallenge })}`,
        async exchangeAndVerify() { return { ok: false, kind: "exchange_failed", reason: "not-called" }; } } });
    const redirect = await upstream.handleAuthorize(request({ response_type: "code", client_id: clientId,
      redirect_uri: "https://client.example.com/callback", code_challenge: pkceChallenge(verifier),
      code_challenge_method: "S256", scope: "mcp:read", state: "client-state" }));
    const location = new URL(String(redirect.headers.location));
    assert.equal(location.searchParams.get("state"), "aVJuDkF0Up6A2HpS9lc9kMfljZGvqviyN1OFqeiFn7Q");
    assert.equal(location.searchParams.get("nonce"), "cAt_FyObYeohst4tPSLauOB1VkTAjxkwCX-2EqZbyRs");
    assert.equal(location.searchParams.get("code_challenge"), "X8N7TM3E3rH9qhdfM9BJRkFEZlHg21_nKTV29QPqzAQ");
    const cookie = String(redirect.headers["set-cookie"]); const end = cookie.indexOf(";");
    const flowToken = cookie.slice(cookie.indexOf("=") + 1, end);
    assert.equal(decodeJwt(flowToken).jti, "upf_TaHzNJ_5U6NYrXUZhGA2Cp19UqQuexETCcxIAjaybHE");
  } finally { await store.close(); }
});

function request(
  query: NormRequest["query"], body?: unknown, headers: NormRequest["headers"] = {},
): NormRequest {
  return { query, body, headers, ip: "192.0.2.10" };
}
