import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import type { ClientRegistration } from "../src/ports/client-store.ts";
import { openSqliteStore } from "../src/store/sqlite.ts";
import { runClientStoreConformance } from "./lib/client-store-conformance.ts";

const WEB: ClientRegistration = {
  clientId: "mcpdc_0123456789abcdef0123456789abcdef",
  redirectUris: ["https://client.test/callback"],
  applicationType: "web",
  issuedAtEpoch: 1,
};

runClientStoreConformance("SqliteStore", () => openSqliteStore(":memory:"));

function signingJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "sqlite-client" } as JWK;
}

test("SqliteStore persists DCR user registrations across process replacement", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-client-store-"));
  const file = join(dir, "oauth.sqlite");
  try {
    const first = openSqliteStore(file);
    await first.save(WEB);
    await first.close();

    const reopened = openSqliteStore(file);
    assert.deepEqual(await reopened.find(WEB.clientId), WEB);
    await reopened.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("integration: a DCR registration survives restart and completes authorization-code exchange", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-client-flow-"));
  const file = join(dir, "oauth.sqlite");
  const issuer = "http://127.0.0.1";
  const redirectUri = "http://127.0.0.1:4321/callback";
  const key = signingJwk();
  const clock = { nowMs: () => Date.parse("2026-08-13T12:00:00.000Z") };
  const audit = { async writeAuthEvent() {} };
  const makeConfig = (store: ReturnType<typeof openSqliteStore>) => createBridgeConfig({
    issuer,
    resource: `${issuer}/mcp`,
    consentSigningSecret: "s".repeat(40),
    signingPrivateJwk: key,
    signingKeyId: "sqlite-client",
    redirectAllowlist: [redirectUri],
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: [issuer],
    dcr: { mode: "stored", store },
    dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 3600,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
  try {
    const first = openSqliteStore(file);
    const firstBridge = new Bridge({ config: makeConfig(first), store: first, clock, audit });
    const registration = await firstBridge.handleRegister({
      query: {}, headers: {}, body: { redirect_uris: [redirectUri], application_type: "native" },
    });
    assert.equal(registration.status, 201);
    const clientId = (registration.body as { client_id: string }).client_id;
    await first.close();

    const reopened = openSqliteStore(file);
    const bridge = new Bridge({ config: makeConfig(reopened), store: reopened, clock, audit });
    const verifier = "sqlite-client-verifier-0123456789abcdef012345678901";
    const authorize = await bridge.handleAuthorize({
      query: {
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: pkceChallenge(verifier),
        code_challenge_method: "S256",
        state: "restart",
      },
      headers: {},
      body: undefined,
    }, { subject: "user-1" });
    assert.equal(authorize.status, 200, "the reopened client registration authorizes");
    const consentToken = /name="consent_token" value="([^"]+)"/u.exec(String(authorize.body))?.[1];
    assert.ok(consentToken);
    const approve = await bridge.handleApprove({
      query: {},
      headers: { origin: issuer },
      body: { consent_token: consentToken, approved: "true" },
    });
    assert.equal(approve.status, 302);
    const code = new URL(String(approve.headers.location)).searchParams.get("code");
    assert.ok(code);
    const token = await bridge.handleToken({
      query: {}, headers: {}, body: {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
      },
    });
    assert.equal(token.status, 200);
    assert.equal(typeof (token.body as { access_token: unknown }).access_token, "string");
    await reopened.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
