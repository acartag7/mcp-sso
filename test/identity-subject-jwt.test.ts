import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { importJWK, SignJWT, type JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { signAccessToken, signConsentToken, verifyAccessToken, verifyConsentToken } from "../src/crypto.ts";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { RequestAuthorizer } from "../src/verifier.ts";
import { INVALID_IDENTITY_SUBJECTS, VALID_IDENTITY_SUBJECTS } from "./lib/identity-subject-cases.ts";

const NOW_MS = Date.parse("2026-08-22T10:00:00.000Z");
const clock = { nowMs: () => NOW_MS };

function config(): BridgeConfig {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createBridgeConfig({
    issuer: "https://auth.test", resource: "https://auth.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy-0123456789",
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK,
    signingKeyId: "k", redirectAllowlist: ["https://client.test/callback"],
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"], allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" }, accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

class Audit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}

class ObservedStore extends MemoryStore {
  commits = 0;
  grantReads = 0;
  override async commitConsentApproval(...args: Parameters<MemoryStore["commitConsentApproval"]>) {
    this.commits += 1;
    return super.commitConsentApproval(...args);
  }
  override async findGrantedScopes(...args: Parameters<MemoryStore["findGrantedScopes"]>) {
    this.grantReads += 1;
    return super.findGrantedScopes(...args);
  }
}

async function forgeConsent(subject: string, cfg: BridgeConfig): Promise<string> {
  const now = Math.floor(NOW_MS / 1000);
  return new SignJWT({
    typ: "mcp-sso-consent", jti: "legacy-jti", client_id: "client",
    redirect_uri: "https://client.test/callback", resource: cfg.resource, scope: "mcp:read",
    code_challenge: "A".repeat(43), code_challenge_method: "S256", store_instance: "legacy-store",
  }).setProtectedHeader({ alg: "HS256", typ: "JWT" }).setIssuer(cfg.issuer)
    .setAudience("mcp-sso/consent").setSubject(subject).setIssuedAt(now).setExpirationTime(now + 300)
    .sign(new TextEncoder().encode(cfg.consentSigningSecret));
}

async function forgeAccess(subject: string, cfg: BridgeConfig): Promise<string> {
  const now = Math.floor(NOW_MS / 1000);
  const key = await importJWK(cfg.signingPrivateJwk, "ES256");
  return new SignJWT({ client_id: "client", scope: "mcp:read" })
    .setProtectedHeader({ alg: "ES256", kid: cfg.signingKeyId, typ: "JWT" })
    .setIssuer(cfg.issuer).setAudience(cfg.resource).setSubject(subject)
    .setIssuedAt(now).setExpirationTime(now + 300).sign(key);
}

test("consent and access signers reject the complete malformed subject class", async () => {
  const cfg = config();
  for (const subject of INVALID_IDENTITY_SUBJECTS) {
    await assert.rejects(signConsentToken({
      clientId: "client", redirectUri: "https://client.test/callback", resource: cfg.resource,
      scopes: ["mcp:read"], codeChallenge: "A".repeat(43), codeChallengeMethod: "S256", subject,
    }, cfg, clock));
    await assert.rejects(signAccessToken({ subject, clientId: "client", scopes: ["mcp:read"] }, cfg, clock));
  }
  for (const subject of VALID_IDENTITY_SUBJECTS) {
    assert.equal((await verifyConsentToken(await signConsentToken({
      clientId: "client", redirectUri: "https://client.test/callback", resource: cfg.resource,
      scopes: ["mcp:read"], codeChallenge: "A".repeat(43), codeChallengeMethod: "S256", subject,
    }, cfg, clock), cfg, clock)).subject, subject);
    assert.equal((await verifyAccessToken(await signAccessToken({ subject, clientId: "client", scopes: ["mcp:read"] }, cfg, clock), cfg, clock)).subject, subject);
  }
});

test("signed legacy consent subjects fail before Deny, grant lookup, jti consumption, or code storage", async () => {
  for (const subject of ["legacy ", "legacy\uFFFD"]) {
    for (const approved of [false, true]) {
      const cfg = config(); const store = new ObservedStore(); const audit = new Audit();
      const bridge = new Bridge({ config: cfg, store, clock, audit });
      const response = await bridge.handleApprove({
        query: {}, body: { consent_token: await forgeConsent(subject, cfg), approved: String(approved) },
        headers: { origin: "https://auth.test" }, ip: "203.0.113.9",
      });
      assert.equal(response.status, 400); assert.equal(response.redirect, undefined);
      assert.equal(store.commits, 0); assert.equal(store.grantReads, 0);
      assert.equal(audit.events.some((event) => event.status === "success"), false);
      assert.equal(JSON.stringify(audit.events).includes(subject), false);
    }
  }
});

test("signed legacy access subjects fail before resource authorization or success audit", async () => {
  for (const subject of ["legacy ", "legacy\uFFFD"]) {
    const cfg = config(); const audit = new Audit();
    const authorizer = new RequestAuthorizer({ config: cfg, clock, audit });
    await assert.rejects(authorizer.authorize({ authorization: `Bearer ${await forgeAccess(subject, cfg)}` }));
    assert.equal(audit.events.some((event) => event.status === "success"), false);
    assert.equal(JSON.stringify(audit.events).includes(subject), false);
  }
});
