import assert from "node:assert/strict";
import test from "node:test";
import { CompactSign, generateKeyPair, type CryptoKey } from "jose";
import { captureResponse } from "./parity/captures.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import type { CaptureSpec, CaptureValues, ObservedMessage } from "./parity/types.ts";

const jwtHeader = { alg: "ES256", kid: "capture-key", typ: "JWT" } as const;
const jwtClaims = { sub: "alice", scope: "read" };
const jwtSpec = (name: string): CaptureSpec => ({
  name, source: { bodyPointer: "/token" },
  jwt: { key: "signingPublic", header: jwtHeader, claims: jwtClaims },
});

function response(body: unknown, location = "https://example.test/callback?code=query-value"): ObservedMessage {
  return {
    status: 302,
    headers: { "content-type": "application/json", location },
    body: Buffer.from(JSON.stringify(body), "utf8"),
  };
}

function captureMap(values: CaptureValues, fixtureId: string): Map<string, string> | undefined {
  return values.get(fixtureId);
}

async function expectRunnerError(action: () => Promise<unknown>, message: RegExp): Promise<void> {
  await assert.rejects(action, (error: unknown) => {
    assert.ok(error instanceof FixtureRunnerError);
    assert.match(error.message, message);
    return true;
  });
}

async function signedJwt(privateKey: CryptoKey, claims = jwtClaims): Promise<string> {
  return new CompactSign(Buffer.from(JSON.stringify(claims), "utf8"))
    .setProtectedHeader(jwtHeader).sign(privateKey);
}

test("undefined and empty capture specs do not create an outer entry", async () => {
  const unrelated = new Map([["existing", "value"]]);
  const captures: CaptureValues = new Map([["unrelated", unrelated]]);
  await captureResponse("undefined", undefined, response({ token: "ignored" }), {}, captures);
  await captureResponse("empty", [], response({ token: "ignored" }), {}, captures);
  assert.equal(captures.has("undefined"), false);
  assert.equal(captures.has("empty"), false);
  assert.deepEqual(captures.get("unrelated"), unrelated);
});

test("records body and query captures in declared order", async () => {
  const captures: CaptureValues = new Map();
  await captureResponse("recorded", [
    { name: "body", source: { bodyPointer: "/token" } },
    { name: "query", source: { header: "location", urlQuery: "code" } },
  ], response({ token: "body-value" }), {}, captures);
  assert.deepEqual([...captureMap(captures, "recorded")!.entries()], [
    ["body", "body-value"], ["query", "query-value"],
  ]);
});

test("rejects duplicate names without relying on corpus loading", async () => {
  const captures: CaptureValues = new Map();
  await expectRunnerError(() => captureResponse("duplicate", [
    { name: "same", source: { bodyPointer: "/token" } },
    { name: "same", source: { bodyPointer: "/token" } },
  ], response({ token: "value" }), {}, captures), /duplicate capture name same/u);
  assert.equal(captures.has("duplicate"), false);
});

test("commits no partial entry when a later selector fails", async () => {
  const existing = new Map([["keep", "untouched"]]);
  const captures: CaptureValues = new Map([["other", existing]]);
  await expectRunnerError(() => captureResponse("failed", [
    { name: "first", source: { bodyPointer: "/token" } },
    { name: "second", source: { bodyPointer: "/missing" } },
  ], response({ token: "captured" }), {}, captures), /JSON Pointer did not select/u);
  assert.equal(captures.has("failed"), false);
  assert.deepEqual(captures.get("other"), existing);
});

test("verifies JWT captures and stores the original compact string", async () => {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const token = await signedJwt(privateKey);
  const captures: CaptureValues = new Map();
  await captureResponse("jwt", [jwtSpec("token")], response({ token }), {
    signingPublic: publicKey,
  }, captures);
  assert.equal(captures.get("jwt")?.get("token"), token);
});

test("missing JWT key and invalid JWT leave existing captures unchanged", async () => {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const token = await signedJwt(privateKey);
  const existing = new Map([["keep", "untouched"]]);
  const missingKey: CaptureValues = new Map([["other", existing]]);
  const first: CaptureSpec = { name: "first", source: { bodyPointer: "/first" } };
  await expectRunnerError(() => captureResponse("missing-key", [first, jwtSpec("token")],
    response({ first: "staged", token }), {}, missingKey), /requires signingPublic key/u);
  assert.equal(missingKey.has("missing-key"), false);
  assert.deepEqual(missingKey.get("other"), existing);

  const invalid: CaptureSpec = { ...jwtSpec("token"), jwt: {
    key: "signingPublic", header: jwtHeader, claims: { ...jwtClaims, scope: "write" },
  } };
  const invalidKey: CaptureValues = new Map([["other", existing]]);
  await expectRunnerError(() => captureResponse("invalid-jwt", [first, invalid],
    response({ first: "staged", token }), { signingPublic: publicKey }, invalidKey),
    /captured JWT claims do not match fixture/u);
  assert.equal(invalidKey.has("invalid-jwt"), false);
  assert.deepEqual(invalidKey.get("other"), existing);
});
