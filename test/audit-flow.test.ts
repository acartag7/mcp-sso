// Flow-level verification of the audit sinks (docs/verification.md T1.S1a rows
// S1a.1, S1a.2, S1a.3): drive the REAL authorize->token->refresh flow with a
// sink wired in as the AuditPort — not a direct sink unit test. Asserts the file
// captures the expected event sequence, carries no raw secrets, and that a
// failing sink composed via combineAudit never breaks the flow.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { JWK } from "jose";
import { type BridgeConfig, createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { OAuthAuthorizationUseCase } from "../src/authorize.ts";
import { OAuthTokenUseCase, type TokenResponse } from "../src/token.ts";
import { MemoryStore } from "../src/store/memory.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { AuthAuditEvent, AuditPort } from "../src/ports/audit.ts";
import { JsonlFileAudit } from "../src/audit/jsonl-file.ts";
import { combineAudit } from "../src/audit/combine.ts";

const NOW_MS = Date.parse("2026-07-05T12:00:00.000Z");
const REDIRECT = "https://client.test/callback";
const SUBJECT = "agent@test";

class FakeClock implements ClockPort {
  private ms: number;
  constructor(ms: number) { this.ms = ms; }
  nowMs(): number { return this.ms; }
}

function testPrivateJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "test-key-1" } as JWK;
}

function makeConfig(): BridgeConfig {
  return createBridgeConfig({
    issuer: "https://auth.test",
    resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: testPrivateJwk(),
    signingKeyId: "test-key-1",
    redirectAllowlist: [REDIRECT],
    scopeCatalog: ["mcp:read", "mcp:write"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
}

interface FlowCtx { auth: OAuthAuthorizationUseCase; token: OAuthTokenUseCase; }

function flowWith(audit: AuditPort): FlowCtx {
  const config = makeConfig();
  const clock = new FakeClock(NOW_MS);
  const store = new MemoryStore();
  return {
    auth: new OAuthAuthorizationUseCase({ config, store, clock, audit }),
    token: new OAuthTokenUseCase({ config, store, clock, audit }),
  };
}

async function authorizeAndExchange(ctx: FlowCtx): Promise<{ code: string; tokens: TokenResponse }> {
  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const prepared = await ctx.auth.prepare({
    clientId: "client-1", redirectUri: REDIRECT, responseType: "code",
    codeChallenge: pkceChallenge(verifier), codeChallengeMethod: "S256",
    scope: "mcp:read mcp:write", state: "state-1", subject: SUBJECT,
  });
  const approved = await ctx.auth.approve({
    consentToken: prepared.consentToken, approved: true, origin: "https://auth.test",
  });
  assert.ok(approved.code, "approve mints a code");
  const tokens = await ctx.token.exchangeAuthorizationCode({
    grantType: "authorization_code", code: approved.code, redirectUri: REDIRECT,
    clientId: "client-1", codeVerifier: verifier,
  });
  return { code: approved.code, tokens };
}

async function withDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-flow-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("S1a.1 + S1a.2: authorize->token->refresh with JsonlFileAudit — one valid JSON line per event, expected sequence, no raw secrets", async () => {
  await withDir(async (dir) => {
    const path = join(dir, "audit.jsonl");
    const ctx = flowWith(new JsonlFileAudit(path));
    const { code, tokens } = await authorizeAndExchange(ctx);
    const refreshed = await ctx.token.refresh({
      grantType: "refresh_token", refreshToken: tokens.refresh_token, clientId: "client-1",
    });

    const raw = await readFile(path, "utf8");
    const lines = raw.split("\n").filter((l) => l.length > 0);
    assert.equal(lines.length, 4, "one line per emitted event (prepare, approve, code, refresh)");
    // Every line is valid JSON.
    const parsed = lines.map((l) => JSON.parse(l) as AuthAuditEvent);
    assert.deepEqual(
      parsed.map((e) => e.event),
      ["oauth.authorize.prepare", "oauth.authorize.approve", "oauth.token.authorization_code", "oauth.token.refresh"],
    );
    // S1a.2: no raw auth code / access token / refresh token (old or rotated) in the audit output.
    for (const secret of [code, tokens.access_token, tokens.refresh_token, refreshed.access_token, refreshed.refresh_token]) {
      assert.equal(raw.includes(secret), false, `audit leaked a raw secret: ${secret.slice(0, 6)}…`);
    }
  });
});

test("S1a.3: combineAudit(throwingSink, fileSink) during a flow — flow succeeds, file still written, failure is diagnostic-only", async () => {
  await withDir(async (dir) => {
    const path = join(dir, "audit.jsonl");
    const fileSink = new JsonlFileAudit(path);
    const throwingSink: AuditPort = {
      async writeAuthEvent(): Promise<void> { throw new Error("sink exploded with Bearer LEAKED_ATTEMPT"); },
    };
    const ctx = flowWith(combineAudit(throwingSink, fileSink));

    // The flow MUST succeed — the throwing sink's failure is absorbed by the
    // composite and never reaches the awaited writeAuthEvent in the use-cases.
    const { code, tokens } = await authorizeAndExchange(ctx);
    assert.ok(code);
    assert.ok(tokens.access_token);
    const refreshed = await ctx.token.refresh({
      grantType: "refresh_token", refreshToken: tokens.refresh_token, clientId: "client-1",
    });
    assert.ok(refreshed.access_token);

    const raw = await readFile(path, "utf8");
    const lines = raw.split("\n").filter((l) => l.length > 0);
    assert.equal(lines.length, 4, "the file sink still captured every event despite the sibling throwing");
    // The throwing sink's rejection reason must not be echoed anywhere the file
    // sink writes (it isn't — combineAudit logs a fixed count line to stderr,
    // never the reason), and no secret leaked.
    assert.equal(raw.includes("LEAKED_ATTEMPT"), false);
  });
});
