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
import { test } from "node:test";

import { OAuthError } from "../src/errors.ts";
import { PortFailureError, callPort } from "../src/port-failure.ts";
import { revokeRefreshToken } from "../src/token-revoke.ts";
import type { AuditPort } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { StorePort } from "../src/ports/store.ts";

const clock: ClockPort = { nowMs: () => 1_700_000_000_000 };

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
