import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import Fastify from "fastify";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import type { AuthAuditEvent, AuditPort } from "../src/ports/audit.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import { STORED_DCR_GRANT_GENERATION } from "../src/ports/store.ts";
import { openSqliteStore } from "../src/store/sqlite.ts";

const ISSUER = "http://localhost";
const RESOURCE_A = "http://localhost/mcp";
const RESOURCE_B = "http://localhost:3001/mcp";
const REDIRECT = "http://localhost:4321/callback";
const SUBJECT = "shared-user";
const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

class SharedClients implements ClientStore {
  readonly rows = new Map<string, ClientRegistration>();
  async save(client: ClientRegistration): Promise<void> { this.rows.set(client.clientId, structuredClone(client)); }
  async find(clientId: string): Promise<ClientRegistration | null> { return structuredClone(this.rows.get(clientId) ?? null); }
}

class RecordingAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(structuredClone(event)); }
}

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "release" } as JWK;
}

function config(resource: string, clients: SharedClients, signingPrivateJwk: JWK) {
  return createBridgeConfig({ issuer: ISSUER, resource, consentSigningSecret: "x".repeat(40), signingPrivateJwk, signingKeyId: "release",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"], allowedOrigins: [ISSUER],
    dcr: { mode: "stored", store: clients }, dev: { allowInsecureLocalhost: true }, accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 3600, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300 });
}

function query(clientId: string, verifier: string): string {
  return `/oauth/authorize?${new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
    code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "release" })}`;
}

function durableSnapshot(file: string): string {
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    const tables = ["oauth_auth_codes", "oauth_refresh_token_families", "oauth_refresh_tokens", "oauth_consent_jtis"];
    return JSON.stringify(Object.fromEntries(tables.map((table) => [table, db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()])));
  } finally { db.close(); }
}

releaseTest("RM.8 shared durable OAuth state remains isolated across two shipped Fastify routes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-release-resource-"));
  const sqliteFile = join(dir, "oauth.db");
  const store = openSqliteStore(sqliteFile);
  const clients = new SharedClients();
  const auditA = new RecordingAudit();
  const auditB = new RecordingAudit();
  const key = jwk();
  const configA = config(RESOURCE_A, clients, key);
  const configB = config(RESOURCE_B, clients, key);
  const clock = { nowMs: () => Date.now() };
  const bridgeA = new Bridge({ config: configA, store, clock, audit: auditA });
  const bridgeB = new Bridge({ config: configB, store, clock, audit: auditB });
  const identity = { async verify() { return { ok: true as const, identity: { subject: SUBJECT } }; } };
  const appA = Fastify(); const appB = Fastify();
  await registerOAuthRoutes(appA, { bridge: bridgeA, identity, identityHeader: "x-release" });
  await registerOAuthRoutes(appB, { bridge: bridgeB, identity, identityHeader: "x-release" });
  try {
    const registration = await appA.inject({ method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
      payload: JSON.stringify({ redirect_uris: [REDIRECT], application_type: "native" }) });
    assert.equal(registration.statusCode, 201);
    const clientId = registration.json<{ client_id: string }>().client_id;
    const verifier = "release-resource-verifier-0123456789abcdef012345678901";
    const authorize = await appA.inject({ method: "GET", url: query(clientId, verifier), headers: { "x-release": "ok" } });
    assert.equal(authorize.statusCode, 200);
    const consent = /name="consent_token" value="([^"]+)"/.exec(authorize.body)?.[1];
    assert.ok(consent);

    const beforeConsentB = durableSnapshot(sqliteFile);
    const denyAtB = await appB.inject({ method: "POST", url: "/oauth/authorize/approve", headers: {
      "content-type": "application/x-www-form-urlencoded", origin: ISSUER,
    }, payload: new URLSearchParams({ consent_token: consent, approved: "false" }).toString() });
    assert.equal(denyAtB.statusCode, 400);
    assert.equal(durableSnapshot(sqliteFile), beforeConsentB, "resource B consent denial did not mutate durable state");
    const beforeApproveB = durableSnapshot(sqliteFile);
    const approveAtB = await appB.inject({ method: "POST", url: "/oauth/authorize/approve", headers: {
      "content-type": "application/x-www-form-urlencoded", origin: ISSUER,
    }, payload: new URLSearchParams({ consent_token: consent, approved: "true" }).toString() });
    assert.equal(approveAtB.statusCode, 400);
    assert.equal(durableSnapshot(sqliteFile), beforeApproveB, "resource B consent approval did not mutate durable state");

    const approveAtA = await appA.inject({ method: "POST", url: "/oauth/authorize/approve", headers: {
      "content-type": "application/x-www-form-urlencoded", origin: ISSUER,
    }, payload: new URLSearchParams({ consent_token: consent, approved: "true" }).toString() });
    assert.equal(approveAtA.statusCode, 302, "B did not consume A's consent");
    const code = new URL(approveAtA.headers.location as string).searchParams.get("code"); assert.ok(code);
    const tokenBody = { grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier };
    const beforeCodeB = durableSnapshot(sqliteFile);
    const codeAtB = await appB.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams(tokenBody).toString() });
    assert.equal(codeAtB.statusCode, 400);
    assert.equal(durableSnapshot(sqliteFile), beforeCodeB, "resource B code did not mutate durable state");
    const tokenAtA = await appA.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams(tokenBody).toString() });
    assert.equal(tokenAtA.statusCode, 200, "B did not consume A's code");
    const refresh = tokenAtA.json<{ refresh_token: string }>().refresh_token;

    const beforeRevokeB = durableSnapshot(sqliteFile);
    const beforeRevokeAudit = auditB.events.length;
    const revokeAtB = await appB.inject({ method: "POST", url: "/oauth/revoke", headers: {
      "content-type": "application/x-www-form-urlencoded",
    }, payload: new URLSearchParams({ token: refresh }).toString() });
    assert.equal(revokeAtB.statusCode, 200);
    assert.equal(durableSnapshot(sqliteFile), beforeRevokeB, "resource B revoke did not mutate durable state");
    assert.deepEqual(auditB.events.slice(beforeRevokeAudit).map(({ event, status, reason }) => ({ event, status, reason })), [
      { event: "oauth.revoke", status: "success", reason: "unrecognized_token" },
    ]);

    const beforeRefreshB = durableSnapshot(sqliteFile);
    const refreshAtB = await appB.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refresh, client_id: clientId }).toString() });
    assert.equal(refreshAtB.statusCode, 400);
    assert.equal(durableSnapshot(sqliteFile), beforeRefreshB, "resource B refresh did not mutate durable state");
    const refreshAtA = await appA.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refresh, client_id: clientId }).toString() });
    assert.equal(refreshAtA.statusCode, 200, "B did not rotate or revoke A's refresh token");
    const successor = refreshAtA.json<{ refresh_token: string }>().refresh_token;
    assert.ok(successor); assert.notEqual(successor, refresh, "A rotated to a distinct refresh successor");
    assert.deepEqual(await store.findGrantedScopes(SUBJECT, clientId, new Date().toISOString(), STORED_DCR_GRANT_GENERATION, RESOURCE_B), []);

    const replayAtA = await appA.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refresh, client_id: clientId }).toString() });
    assert.equal(replayAtA.statusCode, 400);
    const successorAtA = await appA.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: successor, client_id: clientId }).toString() });
    assert.equal(successorAtA.statusCode, 400, "A replay revoked A's successor");
    assert.equal(auditB.events.some((event) => event.status === "success"
      && !(event.event === "oauth.revoke" && event.reason === "unrecognized_token")), false,
    "resource B emitted no resource-owning success audit");
  } finally {
    await appA.close(); await appB.close(); await store.close(); await rm(dir, { recursive: true, force: true });
  }
});
