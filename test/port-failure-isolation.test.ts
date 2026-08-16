// A pluggable port is caller-supplied code, so whatever it throws is untrusted
// input on the error channel.
//
// The escape: `asOAuth` picks the public response with
// `error instanceof OAuthError ? error : generic`. `OAuthError` is a published
// export, so a store author who reaches for it produces a value that is
// indistinguishable from one the library raised — and its code/message/status
// then select the response. On `/oauth/revoke` that breaks RFC 7009's
// always-200 rule and turns a store's internal message into an oracle on
// whether the token existed.
//
// These drive the REAL use-cases with a store that throws an OAuthError, and
// assert two things together: the port's value never reaches the caller, and
// the library's OWN OAuthErrors still do. A fix that achieved the first by
// genericising everything would break OAuth conformance, so both halves matter.
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";

import { OAuthError } from "../src/errors.ts";
import { PortFailureError, callPort } from "../src/port-failure.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { OAuthAuthorizationUseCase } from "../src/authorize.ts";
import { OAuthTokenUseCase } from "../src/token.ts";
import { generateRefreshToken, pkceChallenge } from "../src/crypto.ts";
import { registerClient } from "../src/register.ts";
import { revokeRefreshToken } from "../src/token-revoke.ts";
import type { AuditPort } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { StorePort } from "../src/ports/store.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import { MemoryStore } from "../src/store/memory.ts";

const clock: ClockPort = { nowMs: () => 1_700_000_000_000 };
const REDIRECT = "https://client.test/callback";
const RESOURCE = "https://api.test/mcp";
const VERIFIER = "A".repeat(43);

function key(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "port-test" } as JWK;
}

function config(clientStore?: ClientStore, clientCredentials = false): BridgeConfig {
  return createBridgeConfig({
    issuer: "https://auth.test", resource: RESOURCE,
    consentSigningSecret: "port-failure-test-secret-with-enough-entropy",
    signingPrivateJwk: key(), signingKeyId: "port-test",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: clientStore ? { mode: "stored", store: clientStore } : { mode: "stateless" },
    ...(clientCredentials ? { clientCredentials: { enabled: true } } : {}),
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

const quietAudit: AuditPort = { async writeAuthEvent() {} };

function portBoom(): never {
  throw new OAuthError("tenant_alice_at_corp_finance", "token 0xdeadbeef missing from shard 7", 200);
}

async function expectPortFailure(run: () => Promise<unknown>, operation: string): Promise<void> {
  await assert.rejects(run, (error: unknown) => {
    assert.ok(error instanceof PortFailureError, `${operation} must re-cast the port's OAuthError`);
    assert.equal(error.operation, operation);
    assert.doesNotMatch(error.message, /tenant_alice|0xdeadbeef|shard/);
    return true;
  });
}

function recordingAudit(): { audit: AuditPort; events: Array<Record<string, unknown>> } {
  const events: Array<Record<string, unknown>> = [];
  return {
    events,
    audit: { writeAuthEvent: async (event) => { events.push(event as unknown as Record<string, unknown>); } },
  };
}

/** A store whose failure mode is throwing a fully-formed OAuthError — the exact
 *  shape a store author gets by importing the library's own export. */
function hostileStore(): StorePort {
  const boom = (): never => {
    throw new OAuthError("invalid_token", "token 0xdeadbeef missing from shard 7", 401);
  };
  return new Proxy({} as StorePort, { get: () => boom });
}

test("a store's OAuthError never selects the revoke response", async () => {
  const { audit, events } = recordingAudit();
  await assert.rejects(
    () => revokeRefreshToken(
      { store: hostileStore(), clock, audit, resource: "https://api.test/mcp" },
      "some-refresh-token",
    ),
    (error: unknown) => {
      // The store's 401 / "invalid_token" / shard detail must not survive.
      assert.ok(!(error instanceof OAuthError), "a port's throw must not arrive as an OAuthError");
      assert.ok(error instanceof PortFailureError);
      assert.doesNotMatch(String((error as Error).message), /0xdeadbeef|shard/);
      return true;
    },
  );
  // The failure is still accounted for, and the audit carries no token detail.
  const failure = events.find((e) => e.status === "failure");
  assert.ok(failure, `expected a failure audit event, got ${JSON.stringify(events)}`);
  assert.equal(failure.reason, "internal_error");
  assert.doesNotMatch(JSON.stringify(events), /0xdeadbeef|shard|some-refresh-token/);
});

test("callPort re-casts any thrown value, and passes returns through untouched", async () => {
  for (const thrown of [
    new OAuthError("invalid_grant", "port-authored", 400),
    new Error("plain"),
    "a string",
    { code: "shaped_like_an_error" },
    undefined,
  ]) {
    await assert.rejects(
      () => callPort("StorePort", "op", () => Promise.reject(thrown)),
      (error: unknown) => {
        assert.ok(error instanceof PortFailureError, `${String(thrown)} must become a PortFailureError`);
        assert.ok(!(error instanceof OAuthError));
        return true;
      },
    );
  }
  // A RETURNED sentinel is control flow, not failure — rotateRefreshToken's
  // "replayed" and commitConsentApproval's "binding_mismatch" travel this way.
  assert.equal(await callPort("StorePort", "op", () => Promise.resolve("replayed")), "replayed");
  assert.equal(await callPort("StorePort", "op", () => Promise.resolve(null)), null);
});

test("an already-wrapped failure is not re-wrapped", () => {
  const original = new PortFailureError("StorePort", "find", new Error("root"));
  return assert.rejects(
    () => callPort("StorePort", "outer", () => Promise.reject(original)),
    (error: unknown) => {
      assert.equal(error, original, "nesting would bury the originating port and operation");
      return true;
    },
  );
});

test("PortFailureError keeps the original for local logging only", () => {
  const cause = new OAuthError("invalid_token", "secret detail", 401);
  const wrapped = new PortFailureError("StorePort", "findRefreshToken", cause);
  assert.equal(wrapped.cause, cause);
  assert.equal(wrapped.port, "StorePort");
  assert.equal(wrapped.operation, "findRefreshToken");
  // The message an operator sees names the operation, never the cause's text.
  assert.equal(wrapped.message, "StorePort.findRefreshToken failed");
  assert.doesNotMatch(wrapped.message, /secret detail/);
});

test("every response-owning store/client-store call re-casts a port-authored OAuthError", async (t) => {
  await t.test("registration save", async () => {
    const clients: ClientStore = { async save() { portBoom(); }, async find() { return null; } };
    await expectPortFailure(
      () => registerClient({ config: config(clients), clock, audit: quietAudit }, { redirectUris: [REDIRECT] }),
      "save",
    );
  });

  await t.test("stored-client authorization lookup", async () => {
    const clients: ClientStore = { async save() {}, async find() { return portBoom(); } };
    const auth = new OAuthAuthorizationUseCase({ config: config(clients), store: new MemoryStore(), clock, audit: quietAudit });
    await expectPortFailure(() => auth.prepare({
      subject: "operator", clientId: "stored-client", redirectUri: REDIRECT,
      responseType: "code", codeChallenge: pkceChallenge(VERIFIER), codeChallengeMethod: "S256",
      scope: "mcp:read",
    }), "find");
  });

  await t.test("stored grant lookup", async () => {
    const registration: ClientRegistration = {
      clientId: "stored-client", redirectUris: [REDIRECT], applicationType: "web", issuedAtEpoch: 1_700_000_000,
    };
    const clients: ClientStore = { async save() {}, async find() { return registration; } };
    const store = new MemoryStore();
    store.findGrantedScopes = async () => portBoom();
    const auth = new OAuthAuthorizationUseCase({ config: config(clients), store, clock, audit: quietAudit });
    await expectPortFailure(() => auth.prepare({
      subject: "operator", clientId: "stored-client", redirectUri: REDIRECT,
      responseType: "code", codeChallenge: pkceChallenge(VERIFIER), codeChallengeMethod: "S256",
      scope: "mcp:read",
    }), "findGrantedScopes");
  });

  await t.test("approval commit", async () => {
    const store = new MemoryStore();
    const c = config();
    const auth = new OAuthAuthorizationUseCase({ config: c, store, clock, audit: quietAudit });
    const prepared = await auth.prepare({
      subject: "operator", clientId: "stateless-client", redirectUri: REDIRECT,
      responseType: "code", codeChallenge: pkceChallenge(VERIFIER), codeChallengeMethod: "S256",
      scope: "mcp:read",
    });
    store.commitConsentApproval = async () => portBoom();
    await expectPortFailure(() => auth.approve({
      consentToken: prepared.consentToken, approved: true, origin: "https://auth.test",
    }), "commitConsentApproval");
  });

  await t.test("authorization-code consumption", async () => {
    const store = new MemoryStore();
    store.consumeAuthCode = async () => portBoom();
    const token = new OAuthTokenUseCase({ config: config(), store, clock, audit: quietAudit });
    await expectPortFailure(() => token.exchangeAuthorizationCode({
      grantType: "authorization_code", code: "raw-code", redirectUri: REDIRECT,
      clientId: "client", codeVerifier: VERIFIER,
    }), "consumeAuthCode");
  });

  await t.test("initial refresh-family save", async () => {
    const store = new MemoryStore();
    store.consumeAuthCode = async () => ({
      codeHash: "a".repeat(64), clientId: "client", subject: "operator",
      redirectUri: REDIRECT, resource: RESOURCE, scopes: ["mcp:read"],
      codeChallenge: pkceChallenge(VERIFIER), codeChallengeMethod: "S256",
      expiresAt: "2027-01-01T00:00:00.000Z",
    });
    store.saveRefreshToken = async () => portBoom();
    const token = new OAuthTokenUseCase({ config: config(), store, clock, audit: quietAudit });
    await expectPortFailure(() => token.exchangeAuthorizationCode({
      grantType: "authorization_code", code: "raw-code", redirectUri: REDIRECT,
      clientId: "client", codeVerifier: VERIFIER,
    }), "saveRefreshToken");
  });

  await t.test("refresh rotation", async () => {
    const store = new MemoryStore();
    store.rotateRefreshToken = async () => portBoom();
    const token = new OAuthTokenUseCase({ config: config(), store, clock, audit: quietAudit });
    await expectPortFailure(() => token.refresh({
      grantType: "refresh_token", refreshToken: generateRefreshToken("family-abcdefghijkl"), clientId: "client",
    }), "rotateRefreshToken");
  });

  await t.test("post-rotation compensation", async () => {
    const store = new MemoryStore();
    store.rotateRefreshToken = async () => ({
      tokenHash: "b".repeat(64), familyId: "family-abcdefghijkl", previousTokenHash: "a".repeat(64),
      clientId: "actual-client", subject: "operator", resource: RESOURCE,
      scopes: ["mcp:read"], expiresAt: "2027-01-01T00:00:00.000Z",
    });
    store.revokeRefreshTokenFamily = async () => portBoom();
    const token = new OAuthTokenUseCase({ config: config(), store, clock, audit: quietAudit });
    await expectPortFailure(() => token.refresh({
      grantType: "refresh_token", refreshToken: generateRefreshToken("family-abcdefghijkl"), clientId: "wrong-client",
    }), "revokeRefreshTokenFamily");
  });

  await t.test("machine-client authentication lookup", async () => {
    const clients: ClientStore = { async save() {}, async find() { return portBoom(); } };
    const token = new OAuthTokenUseCase({ config: config(clients, true), store: new MemoryStore(), clock, audit: quietAudit });
    await expectPortFailure(() => token.exchangeClientCredentials({
      grantType: "client_credentials", clientId: "mcc_service", clientSecret: "presented-secret",
      scope: "mcp:read",
    }), "find");
  });
});
