import assert from "node:assert/strict";
import test from "node:test";
import { OAuthError } from "../src/errors.ts";
import type { IdentityResult } from "../src/ports/identity.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import { ScriptedIdentity } from "./parity/scripted-identity.ts";
import type { BodyValue, IdentityCheck } from "./parity/types.ts";

const absent: BodyValue = { absent: true };

function value(input: unknown): BodyValue {
  return { value: input };
}

function accepted(subject: string, claims: Record<string, unknown> = {}): IdentityResult {
  return { ok: true, identity: { subject, claims } };
}

function rejected(reason: string): IdentityResult {
  return { ok: false, reason };
}

function check(input: BodyValue, result: IdentityResult): IdentityCheck {
  return { input, result };
}

function runnerError(error: unknown, message: string): boolean {
  assert(error instanceof FixtureRunnerError);
  assert.equal(error.message, message);
  return true;
}

test("ScriptedIdentity matches absent and deeply equal typed values in order", async () => {
  const input = { nested: [{ number: 1, flag: true }, ["x", "y"]] };
  const identity = new ScriptedIdentity([
    check(absent, accepted("absent-subject")),
    check(value(input), accepted("value-subject")),
  ]);

  assert.deepEqual(await identity.verify(undefined), accepted("absent-subject"));
  assert.deepEqual(await identity.verify(structuredClone(input)), accepted("value-subject"));
  identity.assertConsumed();

  const mismatch = new ScriptedIdentity([check(value({ number: "1" }), accepted("subject"))]);
  await assert.rejects(() => mismatch.verify({ number: 1 }), (error: unknown) => {
    assert(runnerError(error, "identity check input mismatch"));
    assert(!String(error).includes("number"));
    assert(!String(error).includes("subject"));
    return true;
  });

  const nullIsPresent = new ScriptedIdentity([check(absent, accepted("subject"))]);
  await assert.rejects(() => nullIsPresent.verify(null), (error: unknown) =>
    runnerError(error, "identity check input mismatch"));

  const undefinedValue = new ScriptedIdentity([check(value(undefined), accepted("subject"))]);
  assert.deepEqual(await undefinedValue.verify(undefined), accepted("subject"));
});

test("ScriptedIdentity rejects empty, excess, and unconsumed scripts", async () => {
  const empty = new ScriptedIdentity([]);
  await assert.rejects(() => empty.verify(undefined), (error: unknown) =>
    runnerError(error, "unmatched IdentityPort.verify call"));

  const excess = new ScriptedIdentity([check(absent, rejected("denied"))]);
  await excess.verify(undefined);
  await assert.rejects(() => excess.verify(undefined), (error: unknown) =>
    runnerError(error, "unmatched IdentityPort.verify call"));

  const unconsumed = new ScriptedIdentity([check(absent, rejected("denied"))]);
  assert.throws(() => unconsumed.assertConsumed(), (error: unknown) =>
    runnerError(error, "all identity checks must be consumed"));
});

test("ScriptedIdentity maps OAuth and generic throws exactly", async () => {
  const oauth = new ScriptedIdentity([{
    input: absent,
    throw: { kind: "oauth", code: "fixture_code", description: "fixture description", status: 403 },
  }]);
  await assert.rejects(() => oauth.verify(undefined), (error: unknown) => {
    assert(error instanceof OAuthError);
    assert.equal(error.code, "fixture_code");
    assert.equal(error.message, "fixture description");
    assert.equal(error.status, 403);
    assert.equal(error.redirect, undefined);
    return true;
  });

  const generic = new ScriptedIdentity([{
    input: absent,
    throw: { kind: "generic" },
  }]);
  await assert.rejects(() => generic.verify(undefined), (error: unknown) => {
    assert(error instanceof Error);
    assert(!(error instanceof OAuthError));
    assert(!(error instanceof FixtureRunnerError));
    assert.equal(error.message, "scripted generic identity failure");
    assert(!error.message.includes("fixture"));
    return true;
  });
});

test("ScriptedIdentity clones accepted and rejected results", async () => {
  const acceptedResult = accepted("accepted-subject", { roles: ["reader"] });
  const rejectedResult = rejected("identity_rejected");
  const identity = new ScriptedIdentity([
    check(value("accepted-1"), acceptedResult),
    check(value("accepted-2"), acceptedResult),
    check(value("rejected-1"), rejectedResult),
    check(value("rejected-2"), rejectedResult),
  ]);

  const firstAccepted = await identity.verify("accepted-1");
  assert(firstAccepted.ok);
  (firstAccepted.identity.claims?.roles as string[]).push("writer");
  assert.deepEqual(await identity.verify("accepted-2"), acceptedResult);

  const firstRejected = await identity.verify("rejected-1");
  assert(!firstRejected.ok);
  firstRejected.reason = "mutated";
  assert.deepEqual(await identity.verify("rejected-2"), rejectedResult);
  identity.assertConsumed();
});

test("ScriptedIdentity snapshots its constructor script", async () => {
  const input = { nested: ["original"] };
  const result = accepted("original-subject", { role: "reader" });
  const checks = [check(value(input), result)];
  const identity = new ScriptedIdentity(checks);

  input.nested[0] = "mutated";
  assert(result.ok);
  result.identity.subject = "mutated-subject";
  checks.length = 0;

  assert.deepEqual(
    await identity.verify({ nested: ["original"] }),
    accepted("original-subject", { role: "reader" }),
  );
  identity.assertConsumed();
});
