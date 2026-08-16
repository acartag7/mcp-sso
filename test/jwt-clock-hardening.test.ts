import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { importJWK, SignJWT, type JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import {
  signAccessToken, signConsentToken, verifyAccessToken, verifyConsentToken,
} from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import type { AuthAuditEvent, AuditPort } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { RequestAuthorizer } from "../src/verifier.ts";
import { signFlowToken } from "../src/adapters/upstream-flow-internals.ts";

const NOW_MS = Date.parse("2026-07-26T12:00:00.000Z");
const MIN_CANONICAL_MS = Date.parse("0000-01-01T00:00:00.000Z");
const MAX_CANONICAL_MS = Date.parse("9999-12-31T23:59:59.999Z");
const APPROVAL_OFFSET_MS = 60_000;

class ScriptedClock implements ClockPort {
  reads = 0;
  private readonly values: number[];
  constructor(values: number[]) {
    this.values = values;
  }
  nowMs(): number {
    const value = this.values[Math.min(this.reads, this.values.length - 1)];
    this.reads += 1;
    if (value === undefined) throw new Error("clock script is empty");
    return value;
  }
}

class MemoryAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> {
    this.events.push(event);
  }
}

const throwingAudit: AuditPort = {
  async writeAuthEvent(): Promise<void> { throw new Error("audit unavailable"); },
};

function makeConfig(): BridgeConfig {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createBridgeConfig({
    issuer: "https://auth.test",
    resource: "https://api.test/mcp",
    consentSigningSecret: "clock-test-consent-secret-with-enough-entropy",
    signingPrivateJwk: {
      ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "clock-test",
    } as JWK,
    signingKeyId: "clock-test",
    redirectAllowlist: ["https://client.test/callback"],
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 1,
    refreshTokenTtlSeconds: 60,
    consentTokenTtlSeconds: 1,
    authorizationCodeTtlSeconds: 60,
  });
}

const config = makeConfig();
const issuedClock: ClockPort = { nowMs: () => NOW_MS - 2_000 };

function isOAuth(code: string, status: number): (error: unknown) => boolean {
  return (error) =>
    error instanceof OAuthError && error.code === code && error.status === status;
}

async function expiredAccessToken(): Promise<string> {
  return signAccessToken(
    { subject: "operator", clientId: "client-1", scopes: ["mcp:read"] },
    config,
    issuedClock,
  );
}

async function expiredConsentToken(): Promise<string> {
  return signConsentToken({
    clientId: "client-1",
    redirectUri: "https://client.test/callback",
    resource: config.resource,
    scopes: ["mcp:read"],
    codeChallenge: "A".repeat(43),
    codeChallengeMethod: "S256",
    subject: "operator",
  }, config, issuedClock);
}

async function validAccessToken(): Promise<string> {
  return accessTokenAt(NOW_MS);
}

async function accessTokenAt(nowMs: number): Promise<string> {
  return signAccessToken(
    { subject: "operator", clientId: "client-1", scopes: ["mcp:read"] },
    config,
    { nowMs: () => nowMs },
  );
}

async function accessTokenWithExpiry(exp: number | undefined): Promise<string> {
  const key = await importJWK(config.signingPrivateJwk, "ES256");
  const token = new SignJWT({ client_id: "client-1", scope: "mcp:read" })
    .setProtectedHeader({ alg: "ES256", kid: config.signingKeyId, typ: "JWT" })
    .setIssuer(config.issuer)
    .setSubject("operator")
    .setAudience(config.resource)
    .setIssuedAt(Math.floor(NOW_MS / 1000));
  if (exp !== undefined) token.setExpirationTime(exp);
  return token.sign(key);
}

async function validConsentToken(): Promise<string> {
  return consentTokenAt(NOW_MS);
}

async function consentTokenAt(nowMs: number): Promise<string> {
  return signConsentToken({
    clientId: "client-1",
    redirectUri: "https://client.test/callback",
    resource: config.resource,
    scopes: ["mcp:read"],
    codeChallenge: "A".repeat(43),
    codeChallengeMethod: "S256",
    subject: "operator",
  }, config, { nowMs: () => nowMs });
}

async function flowTokenAt(nowMs: number): Promise<string> {
  return await signFlowToken({
    secret: config.consentSigningSecret,
    issuer: config.issuer,
    callbackPath: "/oauth/callback",
    clock: { nowMs: () => nowMs },
    jti: "upf_clock_boundary",
    state: "state",
    nonce: "nonce",
    codeVerifier: "v".repeat(43),
    params: { client_id: "client-1" },
    ttlSeconds: 1,
  });
}

test("verifyAccessToken rejects an expired JWT under a NaN clock", async () => {
  const clock = new ScriptedClock([Number.NaN]);
  await assert.rejects(
    verifyAccessToken(await expiredAccessToken(), config, clock),
    isOAuth("invalid_token", 401),
  );
  assert.equal(clock.reads, 1);
});

test("verifyAccessToken requires exp and preserves the exact expiry boundary", async () => {
  const now = Math.floor(NOW_MS / 1000);
  const clock: ClockPort = { nowMs: () => NOW_MS };
  await assert.rejects(
    verifyAccessToken(await accessTokenWithExpiry(undefined), config, clock),
    isOAuth("invalid_token", 401),
  );
  await assert.rejects(
    verifyAccessToken(await accessTokenWithExpiry(now), config, clock),
    isOAuth("invalid_token", 401),
  );
  assert.deepEqual(
    await verifyAccessToken(await accessTokenWithExpiry(now + 1), config, clock),
    { subject: "operator", clientId: "client-1", scopes: ["mcp:read"], credentialKind: "interactive" },
  );
});

test("verifyConsentToken rejects an expired JWT under a NaN clock", async () => {
  const clock = new ScriptedClock([Number.NaN]);
  await assert.rejects(
    verifyConsentToken(await expiredConsentToken(), config, clock),
    isOAuth("invalid_consent", 400),
  );
  assert.equal(clock.reads, 1);
});

test("JWT verifiers reject every non-finite or non-canonical snapshot", async () => {
  const invalidTimes = [
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    0.5,
    MIN_CANONICAL_MS - 1,
    MAX_CANONICAL_MS + 1,
  ];
  const accessToken = await expiredAccessToken();
  const consentToken = await expiredConsentToken();
  for (const invalidTime of invalidTimes) {
    const testedAccessToken = invalidTime === MAX_CANONICAL_MS + 1
      ? await accessTokenWithExpiry(Math.floor(invalidTime / 1000) + 1) : accessToken;
    const testedConsentToken = consentToken;
    const accessClock = new ScriptedClock([invalidTime]);
    const consentClock = new ScriptedClock([invalidTime]);
    await assert.rejects(
      verifyAccessToken(testedAccessToken, config, accessClock),
      isOAuth("invalid_token", 401),
    );
    await assert.rejects(
      verifyConsentToken(testedConsentToken, config, consentClock),
      isOAuth("invalid_consent", 400),
    );
    assert.equal(accessClock.reads, 1);
    assert.equal(consentClock.reads, 1);
  }
});

test("JWT verifiers accept their latest canonical upper-bound mint times", async () => {
  const latestAccessMintMs = MAX_CANONICAL_MS - config.accessTokenTtlSeconds * 1000;
  const latestConsentMintMs = MAX_CANONICAL_MS - config.consentTokenTtlSeconds * 1000;
  const accessClock = new ScriptedClock([latestAccessMintMs]);
  const consentClock = new ScriptedClock([latestConsentMintMs]);
  await verifyAccessToken(await accessTokenAt(latestAccessMintMs), config, accessClock);
  const verifiedConsent = await verifyConsentToken(await consentTokenAt(latestConsentMintMs), config, consentClock);
  assert.equal(verifiedConsent.expiresAt, "9999-12-31T23:59:59.000Z");
  assert.equal(accessClock.reads, 1);
  assert.equal(consentClock.reads, 1);
});

test("JWT signers require canonical mint and expiry times", async () => {
  for (const invalidTime of [MIN_CANONICAL_MS - 1, MAX_CANONICAL_MS + 1, Number.MAX_SAFE_INTEGER]) {
    await assert.rejects(accessTokenAt(invalidTime), RangeError);
    await assert.rejects(consentTokenAt(invalidTime), RangeError);
  }
  await accessTokenAt(MAX_CANONICAL_MS - config.accessTokenTtlSeconds * 1000);
  await consentTokenAt(MAX_CANONICAL_MS - config.consentTokenTtlSeconds * 1000);
  await flowTokenAt(MAX_CANONICAL_MS - 1_000);
  await assert.rejects(
    accessTokenAt(MAX_CANONICAL_MS - config.accessTokenTtlSeconds * 1000 + 1),
    RangeError,
  );
  await assert.rejects(
    consentTokenAt(MAX_CANONICAL_MS - config.consentTokenTtlSeconds * 1000 + 1),
    RangeError,
  );
  await assert.rejects(flowTokenAt(MAX_CANONICAL_MS - 999), RangeError);
});

test("RequestAuthorizer reuses one snapshot for expiry rejection and audit", async () => {
  const clock = new ScriptedClock([NOW_MS, Number.NaN]);
  const audit = new MemoryAudit();
  const authorizer = new RequestAuthorizer({ config, clock, audit });
  await assert.rejects(
    authorizer.authorize({ authorization: `Bearer ${await expiredAccessToken()}` }),
    isOAuth("invalid_token", 401),
  );
  assert.equal(clock.reads, 1);
  assert.deepEqual(audit.events, [{
    occurredAt: new Date(NOW_MS).toISOString(),
    event: "auth.request",
    status: "failure",
    reason: "invalid_token",
  }]);
});

test("RequestAuthorizer rejects an invalid initial snapshot without audit", async () => {
  const clock = new ScriptedClock([Number.NaN]);
  const audit = new MemoryAudit();
  const authorizer = new RequestAuthorizer({ config, clock, audit });
  await assert.rejects(
    authorizer.authorize({ authorization: `Bearer ${await expiredAccessToken()}` }),
    isOAuth("invalid_token", 401),
  );
  assert.equal(clock.reads, 1);
  assert.deepEqual(audit.events, []);
});

test("RequestAuthorizer reuses one snapshot on the success exit", async () => {
  const clock = new ScriptedClock([NOW_MS, Number.NaN]);
  const audit = new MemoryAudit();
  const authorizer = new RequestAuthorizer({ config, clock, audit });
  assert.deepEqual(
    await authorizer.authorize({
      authorization: `Bearer ${await validAccessToken()}`,
      requiredScope: "mcp:read",
    }),
    {
      subject: "operator",
      clientId: "client-1",
      scopes: ["mcp:read"],
      credentialKind: "interactive",
    },
  );
  assert.equal(clock.reads, 1);
  assert.deepEqual(audit.events, [{
    occurredAt: new Date(NOW_MS).toISOString(),
    event: "auth.request",
    status: "success",
    clientId: "client-1",
    subject: "operator",
    scopes: ["mcp:read"],
    reason: "mcp:read",
  }]);
});

test("RequestAuthorizer preserves valid and invalid bearer outcomes when a custom audit sink rejects", async () => {
  const authorizer = new RequestAuthorizer({
    config,
    clock: { nowMs: () => NOW_MS },
    audit: throwingAudit,
  });
  assert.deepEqual(
    await authorizer.authorize({
      authorization: `Bearer ${await validAccessToken()}`,
      requiredScope: "mcp:read",
    }),
    {
      subject: "operator",
      clientId: "client-1",
      scopes: ["mcp:read"],
      credentialKind: "interactive",
    },
  );
  await assert.rejects(
    authorizer.authorize({ authorization: "Bearer malformed" }),
    isOAuth("invalid_token", 401),
  );
});

test("Bridge.handleApprove rejects an invalid initial snapshot without audit", async () => {
  const clock = new ScriptedClock([Number.NaN]);
  const audit = new MemoryAudit();
  const store = new MemoryStore();
  const bridge = new Bridge({ config, clock, audit, store });
  try {
    const response = await bridge.handleApprove({
      query: {},
      headers: { origin: "https://evil.test" },
      body: { consent_token: await expiredConsentToken(), approved: "true" },
    });
    assert.equal(response.status, 400);
    assert.equal((response.body as { error?: string }).error, "invalid_consent");
    assert.equal(clock.reads, 1);
    assert.deepEqual(audit.events, []);
  } finally {
    await store.close();
  }
});

test("Bridge.handleApprove reuses one snapshot on the Deny exit", async () => {
  const clock = new ScriptedClock([NOW_MS, Number.NaN]);
  const audit = new MemoryAudit();
  const store = new MemoryStore();
  const bridge = new Bridge({ config, clock, audit, store });
  try {
    const response = await bridge.handleApprove({
      query: {},
      headers: { origin: "https://auth.test" },
      body: { consent_token: await validConsentToken(), approved: "false" },
    });
    assert.equal(response.status, 302);
    const redirect = new URL(response.redirect!);
    assert.equal(redirect.searchParams.get("error"), "access_denied");
    assert.equal(redirect.searchParams.get("iss"), config.issuer);
    assert.equal(clock.reads, 1);
    assert.equal(audit.events[0]?.occurredAt, new Date(NOW_MS).toISOString());
    assert.equal(audit.events[0]?.status, "failure");
    assert.equal(audit.events[0]?.reason, "access_denied");
  } finally {
    await store.close();
  }
});

test("Bridge.handleApprove uses a fresh commit snapshot on the Approve success exit", async () => {
  const commitMs = NOW_MS + 500;
  const clock = new ScriptedClock([NOW_MS, commitMs, Number.NaN]);
  const audit = new MemoryAudit();
  const store = new MemoryStore();
  const bridge = new Bridge({ config, clock, audit, store });
  try {
    const response = await bridge.handleApprove({
      query: {},
      headers: { origin: "https://auth.test" },
      body: { consent_token: await validConsentToken(), approved: "true" },
    });
    assert.equal(response.status, 302);
    assert.ok(new URL(response.redirect!).searchParams.get("code"));
    assert.equal(clock.reads, 2);
    assert.equal(audit.events[0]?.occurredAt, new Date(commitMs).toISOString());
    assert.equal(audit.events[0]?.status, "success");
    assert.equal(audit.events[0]?.event, "oauth.authorize.approve");
  } finally {
    await store.close();
  }
});

test("Bridge.handleApprove accepts both canonical approval-clock boundaries", async () => {
  const boundaries = [MIN_CANONICAL_MS, MAX_CANONICAL_MS - APPROVAL_OFFSET_MS];
  for (const boundary of boundaries) {
    const clock = new ScriptedClock([boundary, boundary, Number.NaN]);
    const audit = new MemoryAudit();
    const store = new MemoryStore();
    const bridge = new Bridge({ config, clock, audit, store });
    try {
      const response = await bridge.handleApprove({
        query: {},
        headers: { origin: "https://auth.test" },
        body: { consent_token: await consentTokenAt(boundary), approved: "true" },
      });
      assert.equal(response.status, 302);
      assert.ok(new URL(response.redirect!).searchParams.get("code"));
      assert.equal(clock.reads, 2);
      assert.equal(audit.events[0]?.occurredAt, new Date(boundary).toISOString());
      assert.equal(audit.events[0]?.status, "success");
    } finally {
      await store.close();
    }
  }
});

test("Bridge.handleApprove audits a backward commit clock without consuming the JTI", async () => {
  const clock = new ScriptedClock([NOW_MS, NOW_MS - 1, NOW_MS + 500]);
  const audit = new MemoryAudit();
  const store = new MemoryStore();
  const bridge = new Bridge({ config, clock, audit, store });
  const consentToken = await validConsentToken();
  try {
    const response = await bridge.handleApprove({
      query: {}, headers: { origin: "https://auth.test" },
      body: { consent_token: consentToken, approved: "true" },
    });
    assert.equal(response.status, 400);
    assert.equal((response.body as { error?: string }).error, "invalid_consent");
    assert.deepEqual(audit.events, [{
      occurredAt: new Date(NOW_MS).toISOString(), event: "oauth.authorize.approve",
      status: "failure", clientId: undefined, subject: undefined,
      redirectHost: undefined, reason: "invalid_consent",
    }]);
    assert.equal(clock.reads, 2, "failure audit must reuse the initial snapshot without another clock read");
    const retry = await bridge.handleApprove({
      query: {}, headers: { origin: "https://auth.test" },
      body: { consent_token: consentToken, approved: "true" },
    });
    assert.equal(retry.status, 302, "an invalid commit snapshot leaves the consent token usable");
  } finally {
    await store.close();
  }
});

test("Bridge.handleApprove preserves the commit-window OAuth error when its failure sink throws", async () => {
  const clock = new ScriptedClock([NOW_MS, NOW_MS - 1, NOW_MS + 500]);
  const store = new MemoryStore();
  const bridge = new Bridge({ config, clock, audit: throwingAudit, store });
  try {
    const response = await bridge.handleApprove({
      query: {}, headers: { origin: "https://auth.test" },
      body: { consent_token: await validConsentToken(), approved: "true" },
    });
    assert.equal(response.status, 400);
    assert.equal((response.body as { error?: string }).error, "invalid_consent");
    assert.equal(clock.reads, 2, "contained audit failure must not trigger another clock read");
  } finally {
    await store.close();
  }
});

test("Bridge.handleApprove rejects a commit clock whose approval TTL crosses the boundary", async () => {
  const invalidCommitMs = MAX_CANONICAL_MS - APPROVAL_OFFSET_MS + 1;
  const clock = new ScriptedClock([NOW_MS, invalidCommitMs, NOW_MS]);
  const audit = new MemoryAudit();
  const store = new MemoryStore();
  const bridge = new Bridge({ config, clock, audit, store });
  const consentToken = await validConsentToken();
  try {
    const response = await bridge.handleApprove({
      query: {},
      headers: { origin: "https://auth.test" },
      body: { consent_token: consentToken, approved: "true" },
    });
    assert.equal(response.status, 400);
    assert.equal((response.body as { error?: string }).error, "invalid_consent");
    assert.equal(clock.reads, 2);
    assert.deepEqual(audit.events, [{
      occurredAt: new Date(NOW_MS).toISOString(), event: "oauth.authorize.approve",
      status: "failure", clientId: undefined, subject: undefined,
      redirectHost: undefined, reason: "invalid_consent",
    }]);
    const retry = await bridge.handleApprove({
      query: {},
      headers: { origin: "https://auth.test" },
      body: { consent_token: consentToken, approved: "true" },
    });
    assert.equal(retry.status, 302, "the invalid commit snapshot did not consume the JTI");
  } finally {
    await store.close();
  }
});

test("Bridge.handleApprove reuses one snapshot for expiry rejection and audit", async () => {
  const clock = new ScriptedClock([NOW_MS, Number.NaN]);
  const audit = new MemoryAudit();
  const store = new MemoryStore();
  const bridge = new Bridge({ config, clock, audit, store });
  try {
    const response = await bridge.handleApprove({
      query: {},
      headers: { origin: "https://auth.test" },
      body: { consent_token: await expiredConsentToken(), approved: "true" },
    });
    assert.equal(response.status, 400);
    assert.equal((response.body as { error?: string }).error, "invalid_consent");
    assert.equal(clock.reads, 1);
    assert.deepEqual(audit.events, [{
      occurredAt: new Date(NOW_MS).toISOString(),
      event: "oauth.authorize.approve",
      status: "failure",
      clientId: undefined,
      subject: undefined,
      redirectHost: undefined,
      reason: "invalid_consent",
    }]);
  } finally {
    await store.close();
  }
});
