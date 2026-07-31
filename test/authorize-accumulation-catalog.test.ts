import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig } from "../src/config.ts";
import { MemoryStore } from "../src/store/memory.ts";
import type { ClientStore, ClientRegistration } from "../src/ports/client-store.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import { sha256Hex } from "../src/crypto.ts";

const REDIRECT = "https://client.example/cb";
const RES = "https://api.test/mcp";
const NOW = Date.parse("2026-07-31T06:00:00.000Z");
class CS implements ClientStore {
  m = new Map<string, ClientRegistration>();
  async save(c: ClientRegistration) { this.m.set(c.clientId, c); }
  async find(id: string) { return this.m.get(id) ?? null; }
}
function jwk(): JWK { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK; }

// Prior-grant accumulation reads HISTORICAL refresh records. When a stored-DCR
// deployment removes a scope from its catalog, an older refresh token can still
// carry it. Before the fix that scope was unioned into the new authorization
// code unchecked: approval succeeded (burning the single-use consent JTI) and
// the exchange then died in storedScopes() as invalid_grant, stranding the user
// with no way to complete the flow. Accumulated scopes are now filtered through
// the selected resource's CURRENT catalog.
test("accumulation cannot resurrect a scope removed from the catalog", async () => {
  const cs = new CS();
  const store = new MemoryStore();
  // Catalog NO LONGER contains mcp:admin — the deployment removed it.
  const config = createBridgeConfig({
    issuer: "https://auth.test", resource: RES,
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: jwk(), signingKeyId: "k",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stored", store: cs },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  } as never);
  await cs.save({ clientId: "opaque-1", redirectUris: [REDIRECT], applicationType: "web" } as never);
  // An OLD refresh token still carries mcp:admin, granted before removal.
  await store.saveRefreshToken({
    tokenHash: sha256Hex("old"), familyId: "fam", previousTokenHash: null,
    clientId: "opaque-1", subject: "user@example", scopes: ["mcp:read", "mcp:admin"],
    expiresAt: new Date(NOW + 9e8).toISOString(), resource: RES, grantGeneration: 1,
  } as never);
  const identity: IdentityPort = { async verify() { return { ok: true, identity: { subject: "user@example" } } as never; } };
  const bridge = new Bridge({ config, store, clock: { nowMs: () => NOW }, audit: { async writeAuthEvent() {} } });
  const resolved = await bridge.resolveIdentity(identity, "tok", "1.2.3.4");
  const page = await bridge.handleAuthorize({ query: {
    response_type: "code", client_id: "opaque-1", redirect_uri: REDIRECT,
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256",
  }, body: undefined, headers: {}, ip: "1.2.3.4" } as never, resolved);
  const ct = /name="consent_token" value="([^"]+)"/.exec(String(page.body))?.[1];
  assert.ok(ct, `consent page expected, got ${page.status}`);
  const approve = await bridge.handleApprove({ query: {}, body: { consent_token: ct, approved: "true" }, headers: { origin: "https://auth.test" }, ip: "1.2.3.4" } as never);
  const code = /[?&]code=([^&]+)/.exec(String(approve.redirect ?? ""))?.[1];
  assert.ok(code, "approve must redirect with a code");
  const tok = await bridge.handleToken({ query: {}, body: {
    grant_type: "authorization_code", code, redirect_uri: REDIRECT,
    client_id: "opaque-1", code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  }, headers: {}, ip: "1.2.3.4" } as never);
  assert.equal(tok.status, 200, `exchange must succeed, got ${tok.status} ${JSON.stringify(tok.body)}`);
  // The removed scope is gone; the still-valid one survives.
  const granted = String((tok.body as { scope?: string }).scope ?? "").split(" ").filter(Boolean).sort();
  assert.deepEqual(granted, ["mcp:read"], "mcp:admin must not be resurrected from the old grant");
});
