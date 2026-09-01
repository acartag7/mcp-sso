import assert from "node:assert/strict";
import test from "node:test";
import type { AuthAuditEvent } from "../src/ports/audit.ts";
import { assertAudit } from "./parity/audit-assertions.ts";
import { RecordingAudit } from "./parity/recording-audit.ts";
import type { AuditAssertion, AuditEvent } from "./parity/types.ts";

const first: AuthAuditEvent = {
  occurredAt: "2026-08-31T10:00:00.000Z",
  event: "oauth.authorize.prepare",
  status: "failure",
  clientId: "first-client",
  scopes: ["mcp:read"],
  reason: "access_denied",
};
const second: AuthAuditEvent = {
  occurredAt: "2026-08-31T10:00:01.000Z",
  event: "auth.request",
  status: "failure",
  clientId: "second-client",
  reason: "invalid_token",
};

function assertion(events: AuditEvent[], absent: Array<Partial<AuditEvent>> = []): AuditAssertion {
  return { events, absent };
}

test("RecordingAudit keeps chronological structured snapshots", async () => {
  const inherited = Object.create({ reason: "inherited-reason" }) as AuthAuditEvent;
  Object.assign(inherited, {
    occurredAt: first.occurredAt,
    event: first.event,
    status: first.status,
    clientId: first.clientId,
    scopes: ["mcp:read"],
  });
  const audit = new RecordingAudit();

  await audit.writeAuthEvent(inherited);
  inherited.clientId = "mutated-client";
  inherited.scopes?.push("mcp:write");
  await audit.writeAuthEvent(second);

  assert.deepStrictEqual(audit.events, [
    {
      occurredAt: first.occurredAt,
      event: first.event,
      status: first.status,
      clientId: first.clientId,
      scopes: ["mcp:read"],
    },
    second,
  ]);
  assert.equal(Object.hasOwn(audit.events[0]!, "reason"), false);
  assert.notStrictEqual(audit.events[0], inherited);
  assert.notStrictEqual(audit.events[0]!.scopes, inherited.scopes);
});

test("assertAudit accepts the exact ordered event list", () => {
  assertAudit([first, second], assertion([first, second], [{ status: "success" }]), "fixture");
});

test("assertAudit rejects missing, extra, reordered, and field-different events", () => {
  const changed = { ...first, status: "success" as const };
  const cases: Array<{ observed: AuthAuditEvent[]; expected: AuditEvent[] }> = [
    { observed: [first], expected: [first, second] },
    { observed: [first, second], expected: [first] },
    { observed: [second, first], expected: [first, second] },
    { observed: [changed], expected: [first] },
  ];

  for (const candidate of cases) {
    assert.throws(
      () => assertAudit(candidate.observed, assertion(candidate.expected), "fixture"),
      /fixture exact audit events/,
    );
  }
});

test("absent audit selectors use own partial fields and omitted-field wildcards", () => {
  assertAudit([first], assertion([first], [
    { status: "success" },
    { event: first.event, reason: "different-reason" },
  ]), "fixture");

  assert.throws(
    () => assertAudit([first], assertion([first], [{ event: first.event }]), "fixture"),
    /fixture forbidden audit selector/,
  );

  const inherited = Object.create({ reason: first.reason }) as AuthAuditEvent;
  Object.assign(inherited, {
    occurredAt: first.occurredAt,
    event: first.event,
    status: first.status,
  });
  assertAudit([inherited], assertion([inherited], [{ reason: first.reason }]), "fixture");
});
