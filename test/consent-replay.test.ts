import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { SignJWT, type JWK, type JWTPayload } from "jose";
import { OAuthAuthorizationUseCase } from "../src/authorize.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { pkceChallenge, verifyConsentToken } from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { SaveAuthCodeInput } from "../src/ports/store.ts";
import { openSqliteStore, type SqliteStore } from "../src/store/sqlite.ts";
import { MemoryStore } from "../src/store/memory.ts";

const START_MS = Date.parse("2026-07-03T12:00:00.000Z");
const ISSUER = "https://auth.test";
const RESOURCE = "https://api.test/mcp";
const REDIRECT = "https://client.test/callback";
const SUBJECT = "agent@test";
const CONSENT_SECRET = randomBytes(48).toString("base64url");
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const SIGNING_JWK = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "consent-replay" } as JWK;

class FakeClock implements ClockPort {
  private ms: number;
  constructor(ms: number) { this.ms = ms; }
  nowMs(): number { return this.ms; }
  set(ms: number): void { this.ms = ms; }
}

class MemoryAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}

class StaticClientStore implements ClientStore {
  async save(): Promise<void> {}
  async find(clientId: string): Promise<ClientRegistration | null> {
    return {
      clientId,
      redirectUris: [REDIRECT],
      applicationType: "web",
      issuedAtEpoch: 0,
    };
  }
}

function makeConfig(consentTokenTtlSeconds: number, clientStore?: ClientStore): BridgeConfig {
  return createBridgeConfig({
    issuer: ISSUER,
    resource: RESOURCE,
    consentSigningSecret: CONSENT_SECRET,
    signingPrivateJwk: SIGNING_JWK,
    signingKeyId: "consent-replay",
    redirectAllowlist: [REDIRECT],
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: [ISSUER],
    dcr: clientStore ? { mode: "stored", store: clientStore } : { mode: "stateless" },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds,
    authorizationCodeTtlSeconds: 300,
  });
}

function instrumentCodeWrites(
  store: SqliteStore, onWrite: (input: SaveAuthCodeInput, expiresAt: string) => void,
): void {
  const commit = store.commitConsentApproval.bind(store);
  store.commitConsentApproval = async (binding, jti, expiresAt, input) => {
    const result = await commit(binding, jti, expiresAt, input);
    if (result === "stored") onWrite(input, expiresAt);
    return result;
  };
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

async function prepareConsent(auth: OAuthAuthorizationUseCase): Promise<string> {
  const prepared = await auth.prepare({
    clientId: "client-1",
    redirectUri: REDIRECT,
    responseType: "code",
    codeChallenge: pkceChallenge("consent-replay-verifier-123456789012345678901234"),
    codeChallengeMethod: "S256",
    scope: "mcp:read",
    state: "consent-replay-state",
    subject: SUBJECT,
  });
  return prepared.consentToken;
}

test("direct consent replay stays rejected through signed exp after shorter-TTL restart and sweep", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-consent-replay-"));
  const file = join(dir, "oauth.sqlite");
  const clock = new FakeClock(START_MS);
  const audit = new MemoryAudit();
  let codeWrites = 0;
  let recordedExpiry: string | undefined;
  let consentToken: string;

  try {
    const mintStore = openSqliteStore(file);
    try {
      const mintAuth = new OAuthAuthorizationUseCase({ config: makeConfig(600), store: mintStore, clock, audit });
      consentToken = await prepareConsent(mintAuth);
    } finally {
      await mintStore.close();
    }

    clock.set(START_MS + 100_000);
    const firstUseStore = openSqliteStore(file);
    try {
      instrumentCodeWrites(firstUseStore, (_input, expiresAt) => {
        codeWrites += 1;
        recordedExpiry ??= expiresAt;
      });
      const firstUseAuth = new OAuthAuthorizationUseCase({ config: makeConfig(60), store: firstUseStore, clock, audit });
      const firstUse = await firstUseAuth.approve({ consentToken, approved: true, origin: ISSUER });
      assert.ok(firstUse.code, "adjacent valid first use still mints one authorization code");
      assert.equal(recordedExpiry, new Date(START_MS + 600_000).toISOString(), "tombstone uses the verified signed exp");
      assert.equal(codeWrites, 1);
    } finally {
      await firstUseStore.close();
    }

    clock.set(START_MS + 161_000);
    const replayStore = openSqliteStore(file);
    try {
      instrumentCodeWrites(replayStore, () => { codeWrites += 1; });
      await replayStore.sweepExpired(new Date(clock.nowMs()).toISOString());
      const replayAuth = new OAuthAuthorizationUseCase({ config: makeConfig(60), store: replayStore, clock, audit });
      await assert.rejects(
        replayAuth.approve({ consentToken, approved: true, origin: ISSUER }),
        (error: unknown) => error instanceof OAuthError && error.code === "invalid_grant" && !error.redirect,
      );
      assert.equal(codeWrites, 1, "replay writes no second authorization code");
      assert.equal(
        audit.events.filter((event) => event.event === "oauth.authorize.approve" && event.status === "success").length,
        1,
        "replay emits no second approval-success audit",
      );
    } finally {
      await replayStore.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a consent token minted by one store cannot be redeemed by a split-brain replica", async () => {
  const clock = new FakeClock(START_MS);
  const audit = new MemoryAudit();
  const firstStore = new MemoryStore();
  const secondStore = new MemoryStore();
  try {
    const first = new OAuthAuthorizationUseCase({ config: makeConfig(600), store: firstStore, clock, audit });
    const second = new OAuthAuthorizationUseCase({ config: makeConfig(600), store: secondStore, clock, audit });
    const consentToken = await prepareConsent(first);
    const accepted = await first.approve({ consentToken, approved: true, origin: ISSUER });
    assert.ok(accepted.code, "the minting store accepts the adjacent valid approval");
    await assert.rejects(
      second.approve({ consentToken, approved: true, origin: ISSUER }),
      (error: unknown) => error instanceof OAuthError && error.code === "invalid_consent",
    );
    assert.equal(
      audit.events.filter((event) => event.event === "oauth.authorize.approve" && event.status === "success").length,
      1,
      "the independent store emits no second success",
    );
  } finally {
    await firstStore.close();
    await secondStore.close();
  }
});

test("rotating a store binding invalidates old consent and permits a new flow", async () => {
  const clock = new FakeClock(START_MS);
  const audit = new MemoryAudit();
  const store = new MemoryStore();
  try {
    const auth = new OAuthAuthorizationUseCase({ config: makeConfig(600), store, clock, audit });
    const oldConsent = await prepareConsent(auth);
    await store.rotateStoreInstanceId();
    await assert.rejects(
      auth.approve({ consentToken: oldConsent, approved: true, origin: ISSUER }),
      (error: unknown) => error instanceof OAuthError && error.code === "invalid_consent",
    );
    const newConsent = await prepareConsent(auth);
    const accepted = await auth.approve({ consentToken: newConsent, approved: true, origin: ISSUER });
    assert.ok(accepted.code, "a flow minted after rotation succeeds");
  } finally {
    await store.close();
  }
});

test("authorization construction rejects stores without a valid instance binding", async () => {
  const clock = new FakeClock(START_MS);
  const audit = new MemoryAudit();
  const missingStore = new MemoryStore();
  const missing = missingStore as unknown as Omit<MemoryStore, "getStoreInstanceId">;
  Object.defineProperty(missing, "getStoreInstanceId", { value: undefined });
  assert.throws(
    () => new OAuthAuthorizationUseCase({ config: makeConfig(600), store: missing as unknown as MemoryStore, clock, audit }),
    /getStoreInstanceId is required/,
  );
  const noRotation = new MemoryStore();
  Object.defineProperty(noRotation, "rotateStoreInstanceId", { value: undefined });
  assert.throws(
    () => new OAuthAuthorizationUseCase({ config: makeConfig(600), store: noRotation, clock, audit }),
    /rotateStoreInstanceId is required/,
  );
  const noAtomicApproval = new MemoryStore();
  Object.defineProperty(noAtomicApproval, "commitConsentApproval", { value: undefined });
  assert.throws(
    () => new OAuthAuthorizationUseCase({ config: makeConfig(600), store: noAtomicApproval, clock, audit }),
    /commitConsentApproval is required/,
  );
  const malformed = new MemoryStore();
  malformed.getStoreInstanceId = async () => "not base64url!";
  const auth = new OAuthAuthorizationUseCase({ config: makeConfig(600), store: malformed, clock, audit });
  await assert.rejects(prepareConsent(auth), /store instance id must be 22-128 base64url characters/);
  await missingStore.close();
  await noRotation.close();
  await noAtomicApproval.close();
  await malformed.close();
});

test("approval delayed across signed exp cannot race a sweep into a second code", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-consent-race-"));
  const file = join(dir, "oauth.sqlite");
  const clock = new FakeClock(START_MS);
  const audit = new MemoryAudit();
  const clients = new StaticClientStore();
  let codeWrites = 0;

  try {
    const mintStore = openSqliteStore(file);
    let consentToken: string;
    try {
      const mintAuth = new OAuthAuthorizationUseCase({ config: makeConfig(600, clients), store: mintStore, clock, audit });
      consentToken = await prepareConsent(mintAuth);
      instrumentCodeWrites(mintStore, () => { codeWrites += 1; });
      clock.set(START_MS + 100_000);
      const firstUse = await mintAuth.approve({ consentToken, approved: true, origin: ISSUER });
      assert.ok(firstUse.code);
      assert.equal(codeWrites, 1);
    } finally {
      await mintStore.close();
    }

    clock.set(START_MS + 599_000);
    const raceStore = openSqliteStore(file);
    try {
      instrumentCodeWrites(raceStore, () => { codeWrites += 1; });
      const findStarted = deferred();
      const resumeFind = deferred();
      const findGrantedScopes = raceStore.findGrantedScopes.bind(raceStore);
      raceStore.findGrantedScopes = async (...args) => {
        findStarted.resolve();
        await resumeFind.promise;
        return await findGrantedScopes(...args);
      };
      const replayAuth = new OAuthAuthorizationUseCase({ config: makeConfig(600, clients), store: raceStore, clock, audit });
      const replay = replayAuth.approve({ consentToken, approved: true, origin: ISSUER });
      await findStarted.promise;
      clock.set(START_MS + 601_000);
      await raceStore.sweepExpired(new Date(clock.nowMs()).toISOString());
      resumeFind.resolve();

      await assert.rejects(
        replay,
        (error: unknown) => error instanceof OAuthError && error.code === "invalid_consent" && !error.redirect,
      );
      assert.equal(codeWrites, 1, "the delayed replay writes no second authorization code");
      assert.equal(
        audit.events.filter((event) => event.event === "oauth.authorize.approve" && event.status === "success").length,
        1,
        "the delayed replay emits no second approval-success audit",
      );
    } finally {
      await raceStore.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("verifyConsentToken returns canonical signed expiry and rejects malformed expiry claims", async () => {
  const config = makeConfig(600);
  const clock = new FakeClock(START_MS);
  const valid = await forgeConsentToken(config, Math.floor(START_MS / 1000) + 600);
  assert.equal((await verifyConsentToken(valid, config, clock)).expiresAt, new Date(START_MS + 600_000).toISOString());

  const minCanonicalMs = Date.parse("0000-01-01T00:00:00.000Z");
  const yearZeroClock = new FakeClock(minCanonicalMs);
  const yearZeroExpiry = Math.floor(minCanonicalMs / 1000) + 1;
  assert.equal(
    (await verifyConsentToken(await forgeConsentToken(config, yearZeroExpiry), config, yearZeroClock)).expiresAt,
    "0000-01-01T00:00:01.000Z",
    "a representable negative NumericDate remains valid at the canonical lower boundary",
  );

  const maxCanonicalSeconds = Math.floor(Date.parse("9999-12-31T23:59:59.999Z") / 1000);
  const invalidExpiries: unknown[] = [undefined, "later", 1.5, Number.MAX_SAFE_INTEGER + 1, maxCanonicalSeconds + 1];
  for (const expiry of invalidExpiries) {
    await assert.rejects(
      verifyConsentToken(await forgeConsentToken(config, expiry), config, clock),
      (error: unknown) => error instanceof OAuthError && error.code === "invalid_consent",
      `expiry ${String(expiry)} is rejected`,
    );
  }
});

async function forgeConsentToken(config: BridgeConfig, expiry: unknown): Promise<string> {
  const payload: JWTPayload = {
    typ: "mcp-sso-consent",
    jti: "forged-consent-jti",
    client_id: "client-1",
    redirect_uri: REDIRECT,
    resource: RESOURCE,
    scope: "mcp:read",
    code_challenge: "A".repeat(43),
    code_challenge_method: "S256",
  };
  if (expiry !== undefined) payload.exp = expiry as number;
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(config.issuer)
    .setAudience("mcp-sso/consent")
    .setSubject(SUBJECT)
    .setIssuedAt(Math.floor(START_MS / 1000))
    .sign(new TextEncoder().encode(CONSENT_SECRET));
}
