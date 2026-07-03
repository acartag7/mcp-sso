// Shared end-to-end adapter flow (contracts §9.6). Each framework adapter test
// mounts its app + client and calls runAdapterFlow, so all three are exercised
// identically: metadata -> register -> authorize (consent page) -> approve -> token.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { Bridge } from "../../src/adapters/bridge.ts";
import { createBridgeConfig } from "../../src/config.ts";
import { pkceChallenge } from "../../src/crypto.ts";
import type { IdentityPort } from "../../src/ports/identity.ts";
import { MemoryStore } from "../../src/store/memory.ts";

const NOW_MS = Date.parse("2026-07-03T12:00:00.000Z");
const REDIRECT = "https://client.test/callback";
const SUBJECT = "agent@test";
const STUB_TOKEN = "stub-good";
const IDENTITY_HEADER = "cf-access-jwt-assertion";

class FakeClock { private ms: number; constructor(ms: number) { this.ms = ms; } nowMs(): number { return this.ms; } }
class MemoryAudit { async writeAuthEvent(): Promise<void> {} }

function makeBridge(): Bridge {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const signingPrivateJwk = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK;
  const config = createBridgeConfig({
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "x".repeat(40), signingPrivateJwk, signingKeyId: "k",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  return new Bridge({ config, store: new MemoryStore(), clock: new FakeClock(NOW_MS), audit: new MemoryAudit() });
}

const stubIdentity: IdentityPort = {
  async verify(input: unknown) {
    return input === STUB_TOKEN ? { ok: true, identity: { subject: SUBJECT } } : { ok: false, reason: "bad_token" };
  },
};

export interface AdapterResp { status: number; headers: Record<string, string>; body: string }
export interface AdapterClient {
  get(path: string, headers?: Record<string, string>): Promise<AdapterResp>;
  postForm(path: string, body: Record<string, string>, headers?: Record<string, string>): Promise<AdapterResp>;
  postJson(path: string, body: unknown, headers?: Record<string, string>): Promise<AdapterResp>;
  close?(): Promise<void>;
}

export function runAdapterFlow(name: string, mount: (bridge: Bridge, identity: IdentityPort) => Promise<AdapterClient>): void {
  test(`${name} adapter: metadata -> register -> authorize -> approve -> token`, async () => {
    const client = await mount(makeBridge(), stubIdentity);
    try {
      const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
      const meta = await client.get("/.well-known/oauth-authorization-server");
      assert.equal(meta.status, 200);
      assert.equal(JSON.parse(meta.body).issuer, "https://auth.test");

      const reg = await client.postJson("/oauth/register", { redirect_uris: [REDIRECT] });
      assert.equal(reg.status, 201);
      const clientId = JSON.parse(reg.body).client_id;

      const authPage = await client.get(`/oauth/authorize?${new URLSearchParams({
        response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
        code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "s1",
      })}`, { [IDENTITY_HEADER]: STUB_TOKEN });
      assert.equal(authPage.status, 200);
      assert.match(authPage.body, /Approve/);
      const consentToken = /name="consent_token" value="([^"]+)"/.exec(authPage.body)?.[1];
      assert.ok(consentToken, "consent token in page");

      const approve = await client.postForm("/oauth/authorize/approve", { consent_token: consentToken as string, approved: "true" }, { origin: "https://auth.test" });
      assert.equal(approve.status, 302);
      const code = new URL(approve.headers.location as string).searchParams.get("code");
      assert.ok(code);

      const token = await client.postForm("/oauth/token", { grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier });
      assert.equal(token.status, 200);
      assert.match(JSON.parse(token.body).access_token, /^[^.]+\.[^.]+\.[^.]+$/);
    } finally {
      await client.close?.();
    }
  });
}
