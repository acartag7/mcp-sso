import assert from "node:assert/strict";
import test from "node:test";
import { buildUnauthorizedChallenge } from "../src/challenge.ts";
import { createBridgeConfig } from "../src/config.ts";
import { signAccessToken } from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import { noopAudit } from "../src/ports/audit.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { RequestAuthorizer, type RequestAuthInput } from "../src/verifier.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import { privateJwk } from "./parity/keys.ts";
import {
  protectedOutcome, type HostOutcome, type ProtectedAuthorizer,
} from "./parity/protected-handler.ts";
import type { HeaderMap, ProtectedResource } from "./parity/types.ts";

const ISSUER = "https://api.example.com";
const RESOURCE = "https://api.example.com/mcp";
const LISTED_ORIGIN = "https://console.example.com";
const JSON_RPC_CONTENT_TYPE = "application/json; charset=utf-8";

const clock = new SystemClock();
const config = createBridgeConfig({
  issuer: ISSUER, resource: RESOURCE,
  consentSigningSecret: "fixture-only-consent-key-00000002",
  signingPrivateJwk: await privateJwk("keys/signing-private.pem"),
  signingKeyId: "fixture-signing-key-1",
  redirectAllowlist: ["https://client.example.com/callback"], redirectAllowlistMode: "replace",
  scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
  allowedOrigins: [ISSUER, LISTED_ORIGIN], dcr: { mode: "stateless" },
  accessTokenTtlSeconds: 300, refreshTokenTtlSeconds: 3600,
  consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
});
const authorizer = new RequestAuthorizer({ config, clock, audit: noopAudit });

async function bearer(scopes: string[]): Promise<string> {
  const token = await signAccessToken(
    { subject: "fixture-subject", clientId: "fixture-client", scopes }, config, clock,
  );
  return `Bearer ${token}`;
}

const READ_TOKEN = await bearer(["mcp:read"]);
const AUTHORIZED = { authorization: [READ_TOKEN] };
const SUCCESS = {
  status: 200, headers: { "content-type": "application/json" }, body: { value: "ok" },
} satisfies NonNullable<ProtectedResource["success"]>;

function spyOn(inner: ProtectedAuthorizer): { authorizer: ProtectedAuthorizer; calls: RequestAuthInput[] } {
  const calls: RequestAuthInput[] = [];
  return {
    calls,
    authorizer: { authorize: async (input) => { calls.push(input); return await inner.authorize(input); } },
  };
}

const throwingAuthorizer: ProtectedAuthorizer = {
  authorize: async () => { throw new Error("identity provider unreachable"); },
};

function run(options: {
  distinct?: Record<string, string[] | undefined>;
  authorizer?: ProtectedAuthorizer;
  protectedResource?: ProtectedResource;
}): Promise<HostOutcome> {
  return protectedOutcome({
    distinct: options.distinct ?? {},
    authorizer: options.authorizer ?? authorizer,
    config,
    protectedResource: options.protectedResource ?? { requiredScope: null, success: SUCCESS },
  });
}

function succeeding(headers: HeaderMap, body: NonNullable<ProtectedResource["success"]>["body"], status = 200): ProtectedResource {
  return { requiredScope: null, success: { status, headers, body } };
}

function jsonRpcError(message: string): unknown {
  return { jsonrpc: "2.0", error: { code: -32001, message }, id: null };
}

function decoded(outcome: HostOutcome): unknown {
  return JSON.parse(outcome.body.toString("utf8"));
}

function challengeFor(code: string, description: string): string {
  return buildUnauthorizedChallenge(config, {
    scope: config.scopeCatalog, error: code, errorDescription: description,
  });
}

test("two Origin occurrences are refused without consulting the authorizer", async () => {
  const spy = spyOn(authorizer);
  const outcome = await run({
    distinct: { ...AUTHORIZED, origin: [ISSUER, LISTED_ORIGIN] }, authorizer: spy.authorizer,
  });
  assert.equal(outcome.status, 403);
  assert.deepEqual(decoded(outcome), jsonRpcError("Origin not allowed"));
  assert.deepEqual(outcome.headers, { "content-type": JSON_RPC_CONTENT_TYPE });
  assert.equal(Object.hasOwn(outcome.headers, "www-authenticate"), false);
  assert.deepEqual(spy.calls, []);
});

test("an unlisted Origin is refused while the issuer, a listed origin, and no Origin proceed", async () => {
  const refused = await run({ distinct: { ...AUTHORIZED, origin: ["https://evil.example.com"] } });
  assert.equal(refused.status, 403);
  assert.deepEqual(decoded(refused), jsonRpcError("Origin not allowed"));
  assert.equal(Object.hasOwn(refused.headers, "www-authenticate"), false);
  for (const distinct of [
    { ...AUTHORIZED, origin: [ISSUER] },
    { ...AUTHORIZED, origin: [LISTED_ORIGIN] },
    { ...AUTHORIZED },
  ]) {
    assert.equal((await run({ distinct })).status, 200);
  }
});

test("a request with no Authorization header is refused with the library challenge", async () => {
  const outcome = await run({ distinct: {} });
  assert.equal(outcome.status, 401);
  assert.equal(outcome.headers["content-type"], JSON_RPC_CONTENT_TYPE);
  assert.equal(outcome.headers["www-authenticate"], challengeFor("invalid_token", "Bearer token is required"));
  assert.deepEqual(decoded(outcome), jsonRpcError("invalid_token: Bearer token is required"));
});

test("a valid token without the required scope carries the verifier's own status and code", async () => {
  let raised: unknown;
  try { await authorizer.authorize({ authorization: READ_TOKEN, requiredScope: "mcp:write" }); }
  catch (error) { raised = error; }
  assert.ok(raised instanceof OAuthError);
  assert.equal(raised.status, 403);
  assert.equal(raised.code, "insufficient_scope");

  const outcome = await run({
    distinct: AUTHORIZED, protectedResource: { requiredScope: "mcp:write", success: SUCCESS },
  });
  assert.equal(outcome.status, raised.status);
  assert.deepEqual(decoded(outcome), jsonRpcError(`${raised.code}: ${raised.message}`));
  assert.equal(outcome.headers["www-authenticate"], challengeFor(raised.code, raised.message));
});

test("a throwable that is not an OAuthError becomes invalid_token 401 with no port text", async () => {
  const outcome = await run({ distinct: AUTHORIZED, authorizer: throwingAuthorizer });
  assert.equal(outcome.status, 401);
  assert.deepEqual(decoded(outcome), jsonRpcError("invalid_token: Bearer token is invalid"));
  assert.equal(outcome.headers["www-authenticate"], challengeFor("invalid_token", "Bearer token is invalid"));
  assert.equal(outcome.body.toString("utf8").includes("identity provider unreachable"), false);
});

test("a null required scope reaches authorize with no requiredScope property", async () => {
  const unscoped = spyOn(authorizer);
  const outcome = await run({ distinct: AUTHORIZED, authorizer: unscoped.authorizer });
  assert.equal(outcome.status, 200);
  assert.equal(unscoped.calls.length, 1);
  assert.equal(Object.hasOwn(unscoped.calls[0]!, "requiredScope"), false);

  const scoped = spyOn(authorizer);
  await run({
    distinct: AUTHORIZED, authorizer: scoped.authorizer,
    protectedResource: { requiredScope: "mcp:read", success: SUCCESS },
  });
  assert.equal(scoped.calls[0]?.requiredScope, "mcp:read");
});

test("the success response encodes its body according to the stated Content-Type", async () => {
  const cases: Array<{ resource: ProtectedResource; expected: string }> = [
    { resource: succeeding({ "content-type": "application/json" }, { value: "ok" }), expected: '"ok"' },
    { resource: succeeding({ "content-type": "application/json" }, { value: { a: 1 } }), expected: '{"a":1}' },
    { resource: succeeding({ "content-type": "application/json" }, { absent: true }), expected: "" },
    { resource: succeeding({ "content-type": "text/plain; charset=utf-8" }, { value: "ok" }), expected: "ok" },
  ];
  for (const { resource, expected } of cases) {
    const outcome = await run({ distinct: AUTHORIZED, protectedResource: resource });
    assert.equal(outcome.body.toString("utf8"), expected);
    assert.equal(outcome.body.byteLength, Buffer.byteLength(expected, "utf8"));
  }
});

test("the success response returns the fixture status and its exact header occurrences", async () => {
  const resource = succeeding(
    { "content-type": "application/json", "set-cookie": ["first=1", "second=2"] },
    { absent: true }, 204,
  );
  const outcome = await run({ distinct: AUTHORIZED, protectedResource: resource });
  assert.equal(outcome.status, 204);
  assert.deepEqual(outcome.headers, {
    "content-type": "application/json", "set-cookie": ["first=1", "second=2"],
  });
  assert.deepEqual(outcome.headers["set-cookie"], ["first=1", "second=2"]);
  assert.equal(outcome.body.byteLength, 0);
});

test("a fixture with no success response fails the run instead of answering", async () => {
  const spy = spyOn(authorizer);
  await assert.rejects(
    run({
      distinct: AUTHORIZED, authorizer: spy.authorizer,
      protectedResource: { requiredScope: null },
    }),
    (error: unknown) => error instanceof FixtureRunnerError
      && /protectedResource\.success/.test(error.message),
  );
  assert.equal(spy.calls.length, 1);
});

test("a capture reference in a success header fails the run", async () => {
  const headers: HeaderMap = {
    "x-request-id": { $capture: { fixture: "08/chain-start", name: "request-id", format: "raw" } },
  };
  await assert.rejects(
    run({ distinct: AUTHORIZED, protectedResource: succeeding(headers, { absent: true }) }),
    (error: unknown) => error instanceof FixtureRunnerError && /capture/.test(error.message),
  );
});

test("a success header value carrying CR or LF fails the run", async () => {
  for (const value of ["one\r\nx-injected: 1", "one\nx-injected: 1", "one\rx-injected: 1"]) {
    await assert.rejects(
      run({
        distinct: AUTHORIZED,
        protectedResource: succeeding({ "x-note": value }, { absent: true }),
      }),
      (error: unknown) => error instanceof FixtureRunnerError && /CR or LF/.test(error.message),
    );
  }
});
