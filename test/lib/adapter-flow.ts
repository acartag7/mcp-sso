// Shared end-to-end adapter flow (contracts §9.6). Each framework adapter test
// mounts its app + client and calls runAdapterFlow, so all three are exercised
// identically: metadata -> register -> authorize (consent page) -> approve -> token,
// plus the verification.md T1.HF identity-rejection parity matrix (HF.1–HF.3).

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { Bridge } from "../../src/adapters/bridge.ts";
import { createBridgeConfig, type DcrMode } from "../../src/config.ts";
import { pkceChallenge } from "../../src/crypto.ts";
import { OAuthError, withRedirect } from "../../src/errors.ts";
import type { AuditPort, AuthAuditEvent } from "../../src/ports/audit.ts";
import type { ClockPort } from "../../src/ports/clock.ts";
import type { IdentityPort } from "../../src/ports/identity.ts";
import type { ClientStore } from "../../src/ports/client-store.ts";
import type { RateLimitPort } from "../../src/ports/rate-limit.ts";
import { MemoryStore } from "../../src/store/memory.ts";
import { runAdapterHeaderFlow } from "./adapter-header-flow.ts";
import { runAdapterFormOccurrenceFlow } from "./adapter-form-occurrence-flow.ts";

const NOW_MS = Date.parse("2026-07-03T12:00:00.000Z");
const REDIRECT = "https://client.test/callback";
const SUBJECT = "agent@test";
const STUB_TOKEN = "stub-good";
const IDENTITY_HEADER = "cf-access-jwt-assertion";

class FakeClock { private ms: number; constructor(ms: number) { this.ms = ms; } nowMs(): number { return this.ms; } }
class MemoryAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}

function makeBridge(
  rateLimit?: RateLimitPort,
  audit: AuditPort = new MemoryAudit(),
  clock: ClockPort = new FakeClock(NOW_MS),
  store = new MemoryStore(),
  dcr: DcrMode = { mode: "stateless" },
): Bridge {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const signingPrivateJwk = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK;
  const config = createBridgeConfig({
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "x".repeat(40), signingPrivateJwk, signingKeyId: "k",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr,
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  return new Bridge({
    config, store, clock, audit,
    ...(rateLimit === undefined ? {} : { rateLimit }),
  });
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
  requestOccurrences(
    method: "GET" | "POST",
    path: string,
    headers: ReadonlyArray<readonly [string, string]>,
    body?: string,
  ): Promise<AdapterResp>;
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
      assert.equal(authPage.headers["cache-control"], "no-store", `${name}: consent response preserves no-store`);
      assert.match(authPage.body, /Approve/);
      const consentToken = /name="consent_token" value="([^"]+)"/.exec(authPage.body)?.[1];
      assert.ok(consentToken, "consent token in page");

      const approve = await client.postForm("/oauth/authorize/approve", { consent_token: consentToken as string, approved: "true" }, { origin: "https://auth.test" });
      assert.equal(approve.status, 302);
      assert.equal(approve.headers["cache-control"], "no-store", `${name}: code redirect preserves no-store`);
      const code = new URL(approve.headers.location as string).searchParams.get("code");
      assert.ok(code);

      const token = await client.postForm("/oauth/token", { grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier });
      assert.equal(token.status, 200);
      assert.match(JSON.parse(token.body).access_token, /^[^.]+\.[^.]+\.[^.]+$/);
    } finally {
      await client.close?.();
    }
  });

  test(`${name} adapter: stored registration limiter outage preserves the direct 503`, async () => {
    let saves = 0;
    const clients: ClientStore = {
      async save() { saves += 1; },
      async find() { return null; },
    };
    const audit = new MemoryAudit();
    const bridge = makeBridge(
      { async check() { throw new Error("limiter unavailable"); } },
      audit,
      undefined,
      undefined,
      { mode: "stored", store: clients },
    );
    const client = await mount(bridge, stubIdentity);
    try {
      const response = await client.postJson("/oauth/register", { redirect_uris: [REDIRECT] });
      assert.equal(response.status, 503);
      assert.equal(response.headers.location, undefined);
      assert.deepEqual(JSON.parse(response.body), {
        error: "temporarily_unavailable",
        error_description: "Rate limiter unavailable; retry later",
      });
      assert.equal(saves, 0);
      assert.deepEqual(audit.events, []);
    } finally {
      await client.close?.();
    }
  });

  test(`${name} adapter: authorize limiter denies before identity verification`, async () => {
    const keys: string[] = [];
    const audit = new MemoryAudit();
    const bridge = makeBridge({ async check(key) { keys.push(key); return false; } }, audit);
    let verifyCalls = 0;
    const identity: IdentityPort = { async verify() {
      verifyCalls += 1;
      return { ok: false, reason: "must_not_run" };
    } };
    const client = await mount(bridge, identity);
    try {
      const response = await client.get("/oauth/authorize");
      assert.equal(response.status, 429);
      assert.equal(response.headers.location, undefined);
      assert.equal(JSON.parse(response.body).error, "temporarily_unavailable");
      assert.equal(verifyCalls, 0, "limiter denial precedes IdentityPort.verify");
      assert.deepEqual(keys, [name === "hono" ? "authorize:unknown" : "authorize:127.0.0.1"]);
      assert.equal(audit.events.some((event) => event.event === "identity.verify"), false);
    } finally {
      await client.close?.();
    }
  });

  test(`${name} adapter: duplicate authorize query values reach the shared rejection boundary`, async () => {
    const audit = new MemoryAudit();
    let verifyCalls = 0;
    const identity: IdentityPort = {
      async verify() {
        verifyCalls += 1;
        return { ok: true, identity: { subject: SUBJECT } };
      },
    };
    const client = await mount(makeBridge(undefined, audit), identity);
    try {
      const params = new URLSearchParams({
        response_type: "code", client_id: "registered-looking-client", redirect_uri: REDIRECT,
        code_challenge: pkceChallenge("correct-horse-battery-staple-0123"),
        code_challenge_method: "S256", scope: "mcp:read", state: "s1",
      });
      params.append("redirect_uri", "https://attacker.test/callback");
      const response = await client.get(`/oauth/authorize?${params}`, { [IDENTITY_HEADER]: STUB_TOKEN });
      assert.equal(response.status, 400);
      assert.equal(response.headers.location, undefined);
      assert.equal(JSON.parse(response.body).error, "invalid_request");
      assert.equal(response.body.includes("attacker.test"), false);
      assert.equal(response.body.includes("consent_token"), false);
      assert.equal(verifyCalls, 0, "duplicate rejection precedes IdentityPort.verify");
      assert.equal(audit.events.some((event) => event.event === "identity.verify"), false);
      assert.equal(audit.events.some((event) => event.event === "oauth.authorize.prepare"), false);
    } finally {
      await client.close?.();
    }
  });

  test(`${name} adapter: revoke limiter denies on the shipped route`, async () => {
    const keys: string[] = [];
    const audit = new MemoryAudit();
    const bridge = makeBridge({ async check(key) { keys.push(key); return false; } }, audit);
    const client = await mount(bridge, stubIdentity);
    try {
      const response = await client.postForm("/oauth/revoke", { token: "rt_not_processed" });
      assert.equal(response.status, 429);
      assert.equal(JSON.parse(response.body).error, "temporarily_unavailable");
      assert.deepEqual(keys, [name === "hono" ? "revoke:unknown" : "revoke:127.0.0.1"]);
      assert.equal(audit.events.length, 0, "denial reaches no revoke audit work");
    } finally {
      await client.close?.();
    }
  });

  test(`${name} adapter: unsupported revoke media cannot become OAuth fields`, async () => {
    const store = new MemoryStore();
    const originalFind = store.findRefreshToken.bind(store);
    let findCalls = 0;
    store.findRefreshToken = async (tokenHash) => {
      findCalls += 1;
      return originalFind(tokenHash);
    };
    const audit = new MemoryAudit();
    const client = await mount(makeBridge(undefined, audit, undefined, store), stubIdentity);
    const body = "token=rt_must_not_be_parsed";
    try {
      const unsupported = await client.requestOccurrences(
        "POST",
        "/oauth/revoke",
        [["Content-Type", "text/plain"]],
        body,
      );
      assert.equal(unsupported.status, 200);
      assert.equal(findCalls, 0, "unsupported bytes never select a token field");
      assert.equal(audit.events.at(-1)?.reason, "unrecognized_token");

      const form = await client.postForm("/oauth/revoke", { token: "rt_must_be_selected" });
      assert.equal(form.status, 200);
      assert.equal(findCalls, 1, "the adjacent URL-encoded path still selects its token field");
    } finally {
      await client.close?.();
    }
  });

  test(`${name} adapter: rejected identity ⇒ direct 401 access_denied with §9.5 body`, async () => {
    // verification.md T1.HF.1: IdentityPort returns { ok: false }. Contracts §9.3:
    // identity not resolved/rejected is a DIRECT error (never a redirect — the
    // redirect_uri is untrusted pre-validation) and §9.5 mandates the RFC 6749
    // §5.2 top-level {error, error_description} shape, NOT the JSON-RPC inner
    // envelope nor a framework-shaped body.
    const client = await mount(makeBridge(), stubIdentity);
    try {
      const auth = await client.get(`/oauth/authorize?${new URLSearchParams({
        response_type: "code", client_id: "anything", redirect_uri: REDIRECT,
        code_challenge: pkceChallenge("correct-horse-battery-staple-0123"), code_challenge_method: "S256", scope: "mcp:read",
      })}`, { [IDENTITY_HEADER]: "not-the-stub-token" });
      assert.equal(auth.status, 401);
      assert.equal(auth.headers.location, undefined, "identity rejection is direct, never a redirect");
      const body = JSON.parse(auth.body);
      assert.deepEqual(Object.keys(body).sort(), ["error", "error_description"], "RFC 6749 §5.2 shape only");
      assert.equal(body.error, "access_denied");
      assert.equal(body.error_description, "Identity rejected");
    } finally {
      await client.close?.();
    }
  });

  test(`${name} adapter: identity OAuthError cannot author code, body, redirect, or arbitrary status`, async () => {
    // HF.2: only 401/403 rejection status survives. Code, description, redirect,
    // and every other status are library-owned.
    for (const [portStatus, expectedStatus, expectedCode] of [
      [401, 401, "access_denied"],
      [403, 403, "access_denied"],
      [200, 500, "internal_error"],
    ] as const) {
      const throwing: IdentityPort = {
        async verify() { throw new OAuthError("tenant_alice_at_corp_finance", "alice@corp not in group Finance", portStatus); },
      };
      const client = await mount(makeBridge(), throwing);
      try {
        const auth = await client.get(`/oauth/authorize?${new URLSearchParams({
          response_type: "code", client_id: "anything", redirect_uri: REDIRECT,
          code_challenge: pkceChallenge("correct-horse-battery-staple-0123"), code_challenge_method: "S256", scope: "mcp:read",
        })}`, { [IDENTITY_HEADER]: "anything" });
        assert.equal(auth.status, expectedStatus);
        assert.equal(auth.headers.location, undefined);
        const body = JSON.parse(auth.body);
        assert.deepEqual(Object.keys(body).sort(), ["error", "error_description"]);
        assert.equal(body.error, expectedCode);
        if (expectedStatus !== 500) assert.equal(body.error_description, "Identity rejected: port_error");
        assert.ok(!auth.body.includes("tenant_alice"), "the port's code must never reach the client");
        assert.ok(!auth.body.includes("alice@corp"), "the port's text must never reach the client");
        assert.ok(!auth.body.includes("Finance"), "nor the group it named");
      } finally {
        await client.close?.();
      }
    }
  });

  test(`${name} adapter: identity OAuthError redirect is ignored pre-validation`, async () => {
    // Identity resolution is pre-validation. A user-supplied IdentityPort must not
    // be able to smuggle a redirect target by throwing an OAuthError with redirect.
    const throwing: IdentityPort = {
      async verify() {
        throw withRedirect(new OAuthError("access_denied", "identity blocked", 401), "https://evil.test/callback", "stolen");
      },
    };
    const client = await mount(makeBridge(), throwing);
    try {
      const auth = await client.get(`/oauth/authorize?${new URLSearchParams({
        response_type: "code", client_id: "anything", redirect_uri: "https://evil.test/callback",
        code_challenge: pkceChallenge("correct-horse-battery-staple-0123"), code_challenge_method: "S256", scope: "mcp:read",
      })}`, { [IDENTITY_HEADER]: "anything" });
      assert.equal(auth.status, 401);
      assert.equal(auth.headers.location, undefined);
      const body = JSON.parse(auth.body);
      assert.deepEqual(Object.keys(body).sort(), ["error", "error_description"]);
      assert.equal(body.error, "access_denied");
      assert.equal(body.error_description, "Identity rejected: port_error");
      assert.ok(!auth.body.includes("evil.test"));
    } finally {
      await client.close?.();
    }
  });

  test(`${name} adapter: identity throws non-OAuth error ⇒ 500 with non-leaking top-level string body`, async () => {
    // verification.md T1.HF.3: a non-OAuth throw inside the handler must become a
    // 500 with a top-level string `error` body (§9.5 shape), NEVER a framework-
    // specific envelope, and must NOT leak the thrown message (a probe with
    // Error("TOP_SECRET_INTERNAL_DETAIL") previously echoed that string in the
    // response on Express and Fastify).
    const secret = "TOP_SECRET_INTERNAL_DETAIL";
    const throwing: IdentityPort = { async verify() { throw new Error(secret); } };
    const client = await mount(makeBridge(), throwing);
    try {
      const auth = await client.get(`/oauth/authorize?${new URLSearchParams({
        response_type: "code", client_id: "anything", redirect_uri: REDIRECT,
        code_challenge: pkceChallenge("correct-horse-battery-staple-0123"), code_challenge_method: "S256", scope: "mcp:read",
      })}`, { [IDENTITY_HEADER]: "anything" });
      assert.equal(auth.status, 500);
      const body = JSON.parse(auth.body);
      assert.deepEqual(Object.keys(body).sort(), ["error", "error_description"], "top-level RFC 6749 §5.2 shape, not a framework envelope");
      assert.equal(body.error, "internal_error");
      assert.equal(typeof body.error_description, "string");
      assert.ok(!JSON.stringify(body).includes(secret), "thrown message must not leak into the response");
    } finally {
      await client.close?.();
    }
  });

  test(`${name} adapter: identity-audit ClockPort failure cannot select the public response`, async () => {
    const secret = "CLOCK_SHARD_INTERNAL_DETAIL";
    const clock: ClockPort = {
      nowMs() { throw new OAuthError("invalid_token", secret, 401); },
    };
    const client = await mount(makeBridge(undefined, new MemoryAudit(), clock), stubIdentity);
    try {
      const auth = await client.get("/oauth/authorize", { [IDENTITY_HEADER]: STUB_TOKEN });
      assert.equal(auth.status, 500);
      const body = JSON.parse(auth.body);
      assert.deepEqual(Object.keys(body).sort(), ["error", "error_description"]);
      assert.equal(body.error, "internal_error");
      assert.ok(!auth.body.includes("invalid_token"));
      assert.ok(!auth.body.includes(secret));
    } finally {
      await client.close?.();
    }
  });

  runAdapterHeaderFlow(name, mount, makeBridge);
  runAdapterFormOccurrenceFlow(name, mount, makeBridge);
}
