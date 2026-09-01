import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { decodeJwt, type JWK } from "jose";
import { Bridge, type BridgeDeps } from "../src/adapters/bridge.ts";
import type { NormRequest } from "../src/adapters/http.ts";
import { createUpstreamRedirectFlow, type UpstreamFlowDeps } from "../src/adapters/upstream-flow.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import {
  generateAuthorizationCode, generateConsentJti, generateRefreshFamilyId, generateRefreshToken, pkceChallenge,
} from "../src/crypto.ts";
import { noopAudit } from "../src/ports/audit.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import type { RedirectIdentityPort } from "../src/ports/identity.ts";
import type { RandomPort } from "../src/ports/random.ts";
import { registerClient } from "../src/register.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { SeededRandom } from "./parity/random.ts";

const NOW = Date.parse("2026-08-31T10:00:00.000Z");
const ISSUER = "https://auth.example.com";
const RESOURCE = "https://api.example.com/mcp";
const REDIRECT = "https://client.example.com/callback";

class Clients implements ClientStore {
  readonly rows = new Map<string, ClientRegistration>();
  async save(client: ClientRegistration): Promise<void> { this.rows.set(client.clientId, client); }
  async find(clientId: string): Promise<ClientRegistration | null> { return this.rows.get(clientId) ?? null; }
}

function config(clients: ClientStore): BridgeConfig {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createBridgeConfig({
    issuer: ISSUER, resource: RESOURCE, consentSigningSecret: "fixture-consent-signing-secret-32-bytes",
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "fixture" } as JWK,
    signingKeyId: "fixture", redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: [ISSUER], dcr: { mode: "stored", store: clients }, accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

function request(query: NormRequest["query"], body?: unknown, headers: NormRequest["headers"] = {}): NormRequest {
  return { query, body, headers, ip: "192.0.2.10" };
}

test("generated helpers use one injected stream and preserve their wire shapes", () => {
  const random = new SeededRandom("fixture-seed");
  const code = generateAuthorizationCode(random);
  const family = generateRefreshFamilyId(random);
  const jti = generateConsentJti(random);
  const refresh = generateRefreshToken(family, random);
  assert.equal(code, "ac_3aRhmOZolk1D85Xe0rGVGQxPqv6_ETsv1QrSsOMPQsA");
  assert.equal(family, "WyAsfw03V77TFR_e0wKO8y-g");
  assert.equal(jti, "UrS_z7qrSsRpFGEoFzElSij9");
  assert.equal(refresh, "rt.WyAsfw03V77TFR_e0wKO8y-g.EdKdoXsgrz273z-IBOUAMRTp8ZjZJaTPI_qfSniFaLw");
  assert.match(code, /^ac_[A-Za-z0-9_-]{43}$/u);
  assert.match(family, /^[A-Za-z0-9_-]{24}$/u);
  assert.match(jti, /^[A-Za-z0-9_-]{24}$/u);
  assert.match(refresh, new RegExp(`^rt\\.${family}\\.[A-Za-z0-9_-]{43}$`, "u"));
});

test("default generated values remain valid and non-repeating", () => {
  const first = generateAuthorizationCode();
  const second = generateAuthorizationCode();
  const refreshA = generateRefreshToken();
  const refreshB = generateRefreshToken();
  assert.match(first, /^ac_[A-Za-z0-9_-]{43}$/u);
  assert.match(refreshA, /^rt\.[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{43}$/u);
  assert.notEqual(first, second);
  assert.notEqual(refreshA, refreshB);
});

test("stored registration consumes injected bytes and applies UUID v4 bits", async () => {
  const clients = new Clients();
  const calls: number[] = [];
  const random: RandomPort = { bytes(length) { calls.push(length); return Uint8Array.from({ length }, (_, i) => i); } };
  const result = await registerClient(
    { config: config(clients), clock: { nowMs: () => NOW }, audit: noopAudit, random },
    { redirectUris: [REDIRECT] },
  );
  assert.deepEqual(calls, [16]);
  assert.equal(result.client_id, "mcpdc_000102030405460788090a0b0c0d0e0f");
  assert.equal(result.client_id.slice(18, 19), "4");
  assert.equal(result.client_id.slice(22, 23), "8");
  assert.equal((await clients.find(result.client_id))?.clientId, result.client_id);
});

test("Bridge captures one random port across grants and the upstream redirect flow", async () => {
  const random = new SeededRandom("bridge-seed");
  const replacement: RandomPort = { bytes() { throw new Error("replacement random port was used"); } };
  const store = new MemoryStore();
  const clients = new Clients();
  const clock = { nowMs: () => NOW };
  const deps: BridgeDeps = { config: config(clients), store, clock, audit: noopAudit,
    rateLimit: { check: async () => true }, random };
  const bridge = new Bridge(deps);
  deps.random = replacement;
  try {
    const registered = await bridge.handleRegister(request({}, { redirect_uris: [REDIRECT] }));
    const clientId = (registered.body as { client_id: string }).client_id;
    assert.equal(clientId, "mcpdc_2b2f980e126e4563a4145b4049667a42");
    const verifier = "fixture-verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
    const consent = await bridge.handleAuthorize(request({ response_type: "code", client_id: clientId,
      redirect_uri: REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256",
      scope: "mcp:read", state: "fixture-state" }), { subject: "subject-fixture" });
    const consentToken = /name="consent_token" value="([^"]+)"/u.exec(String(consent.body))?.[1];
    assert.ok(consentToken);
    assert.equal(decodeJwt(consentToken).jti, "EuDbvaNXh7fQVGTfvEkAJ1fC");
    const approved = await bridge.handleApprove(request({}, { consent_token: consentToken, approved: "true" }, { origin: ISSUER }));
    const code = new URL(String(approved.headers.location)).searchParams.get("code");
    assert.equal(code, "ac_pInhNt29vUiC_sT8h07GB3aiQ_X8LzjIRqXSK_U2Fb4");
    const exchanged = await bridge.handleToken(request({}, { grant_type: "authorization_code", code,
      redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier }));
    const initial = (exchanged.body as { refresh_token: string }).refresh_token;
    assert.equal(initial, "rt.hFhPN6IdJdUJcVRH2vTD0N4e.3uBzXggOdEZuqbw4w_bncBjkLMmwyKTkWuYVWdTztSI");
    const rotated = await bridge.handleToken(request({}, { grant_type: "refresh_token", refresh_token: initial, client_id: clientId }));
    assert.equal((rotated.body as { refresh_token: string }).refresh_token,
      "rt.hFhPN6IdJdUJcVRH2vTD0N4e.pAo-P9yf6lOaN0c4XRJ-TczZaVJuDkF0Up6A2HpS9lc");

    let built: { state: string; nonce: string; codeChallenge: string } | undefined;
    const identity: RedirectIdentityPort = {
      redirectUri: `${ISSUER}/oauth/callback`,
      buildAuthorizationUrl(args) {
        built = args;
        return `https://idp.example.com/authorize?${new URLSearchParams({ state: args.state, nonce: args.nonce, code_challenge: args.codeChallenge })}`;
      },
      async exchangeAndVerify() { return { ok: false, kind: "exchange_failed", reason: "not-called" }; },
    };
    const upstreamDeps: UpstreamFlowDeps = { bridge, identity, store, clock, audit: noopAudit,
      rateLimit: { check: async () => true }, random };
    const flow = createUpstreamRedirectFlow(upstreamDeps);
    upstreamDeps.random = replacement;
    const redirect = await flow.handleAuthorize(request({ response_type: "code", client_id: clientId,
      redirect_uri: REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256",
      scope: "mcp:read", state: "client-state" }));
    assert.equal(redirect.status, 302);
    assert.deepEqual(built, {
      state: "PZDH5Y2Rr6r4sjdThanohZ-0cAt_FyObYeohst4tPSI",
      nonce: "2rjgdVZEwI8ZMAl_thKmW8kboeqIEMUy1jqi1nnReUE",
      codeChallenge: "-K-7YDDKuag_hY2fqQTgx0DkX2RzI36xr70hu9-TeLo",
      codeChallengeMethod: "S256",
    });
    const cookie = String(redirect.headers["set-cookie"]);
    const flowToken = cookie.slice(cookie.indexOf("=") + 1, cookie.indexOf(";"));
    const claims = decodeJwt(flowToken);
    assert.equal(claims.code_verifier, "ZoROad4Zw2EW51DWUi1D8-P7TaHzNJ_5U6NYrXUZhGA");
    assert.equal(claims.jti, "upf_NgqdfVKkLnsREwnMSAI2smxxEtOYDu2j4jKr_ZYTxAc");
  } finally {
    await store.close();
  }
});
