import assert from "node:assert/strict";
import test from "node:test";
import { OAuthError } from "../src/errors.ts";
import type { IdentityResult } from "../src/ports/identity.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import { ScriptedIdentity } from "./parity/scripted-identity.ts";
import type { BodyValue, IdentityCheck } from "./parity/types.ts";

const absent: BodyValue = { absent: true };
const value = (input: unknown): BodyValue => ({ value: input });
const accepted = (subject: string, claims: Record<string, unknown> = {}): IdentityResult =>
  ({ ok: true, identity: { subject, claims } });
const rejected = (reason: string): IdentityResult => ({ ok: false, reason });
const check = (input: BodyValue, result: IdentityResult): IdentityCheck => ({ input, result });

function isRunnerError(error: unknown, message?: string): boolean {
  assert(error instanceof FixtureRunnerError);
  if (message !== undefined) assert.equal(error.message, message);
  return true;
}

test("matches absent, present undefined, and deeply equal typed inputs", async () => {
  const absentIdentity = new ScriptedIdentity([check(absent, accepted("absent"))]);
  await assert.rejects(() => absentIdentity.verify(null), (error: unknown) => isRunnerError(error));
  assert.deepEqual(await absentIdentity.verify(undefined), accepted("absent"));
  assert.throws(() => absentIdentity.assertConsumed(), (error: unknown) =>
    isRunnerError(error, "fixture script call accounting previously failed"));

  const deep = { nested: [{ number: 1, flag: true }, ["x", "y"]] };
  const identity = new ScriptedIdentity([
    check(value(undefined), rejected("undefined-value")),
    check(value(deep), accepted("deep")),
  ]);
  assert.deepEqual(await identity.verify(undefined), rejected("undefined-value"));
  assert.deepEqual(await identity.verify(structuredClone(deep)), accepted("deep"));
  identity.assertConsumed();

  const typed = new ScriptedIdentity([check(value({ number: 1 }), accepted("typed"))]);
  await assert.rejects(() => typed.verify({ number: "1" }), (error: unknown) =>
    isRunnerError(error, "fixture script call does not match the next entry"));
});

test("returned accepted and rejected results are cloned", async () => {
  const admitted = accepted("subject", { roles: ["reader"] });
  const denied = rejected("identity_rejected");
  const identity = new ScriptedIdentity([
    check(value("accepted-1"), admitted), check(value("accepted-2"), admitted),
    check(value("rejected-1"), denied), check(value("rejected-2"), denied),
  ]);
  const firstAccepted = await identity.verify("accepted-1");
  assert(firstAccepted.ok);
  (firstAccepted.identity.claims?.roles as string[]).push("writer");
  assert.deepEqual(await identity.verify("accepted-2"), admitted);
  const firstRejected = await identity.verify("rejected-1");
  assert(!firstRejected.ok);
  firstRejected.reason = "mutated";
  assert.deepEqual(await identity.verify("rejected-2"), denied);
  identity.assertConsumed();
});

test("maps an OAuth throw without a redirect", async () => {
  const outcomes = [
    { code: "unauthorized_fixture", description: "unauthorized fixture", status: 401 },
    { code: "forbidden_fixture", description: "forbidden fixture", status: 403 },
  ] as const;
  const identity = new ScriptedIdentity(outcomes.map((outcome) => ({
    input: absent, throw: { kind: "oauth" as const, ...outcome },
  })));
  for (const outcome of outcomes) {
    await assert.rejects(() => identity.verify(undefined), (error: unknown) => {
      assert(error instanceof OAuthError);
      assert.equal(error.code, outcome.code);
      assert.equal(error.message, outcome.description);
      assert.equal(error.status, outcome.status);
      assert.equal(error.redirect, undefined);
      return true;
    });
  }
  identity.assertConsumed();
});

test("maps a generic throw to fixed non-OAuth text", async () => {
  const fixtureValue = "fixture-authored-input";
  const identity = new ScriptedIdentity([{ input: value(fixtureValue), throw: { kind: "generic" } }]);
  await assert.rejects(() => identity.verify(fixtureValue), (error: unknown) => {
    assert(error instanceof Error);
    assert(!(error instanceof OAuthError));
    assert(!(error instanceof FixtureRunnerError));
    assert.equal(error.message, "scripted generic identity failure");
    assert.equal(error.message.includes(fixtureValue), false);
    return true;
  });
  identity.assertConsumed();
});

test("defensively rejects an unsafe check with no outcome", async () => {
  const malformed = [{ input: absent }] as unknown as IdentityCheck[];
  const identity = new ScriptedIdentity(malformed);
  await assert.rejects(() => identity.verify(undefined), (error: unknown) =>
    isRunnerError(error, "identity check has no result or throw"));
  identity.assertConsumed();
});

test("delegates unconsumed-check accounting", () => {
  const unconsumed = new ScriptedIdentity([check(absent, rejected("denied"))]);
  assert.throws(() => unconsumed.assertConsumed(), (error: unknown) =>
    isRunnerError(error, "fixture script has unconsumed entries"));
});
