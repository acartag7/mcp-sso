// combineAudit — proves the §17.7 / threat-model row 24 contract: fan-out where
// ONE sink's failure never stops the others, and the composite never rejects.

import assert from "node:assert/strict";
import { test } from "node:test";
import { combineAudit } from "../src/audit/combine.ts";
import type { AuthAuditEvent, AuditPort } from "../src/ports/audit.ts";

const event: AuthAuditEvent = {
  occurredAt: "2026-07-05T12:00:00.000Z",
  event: "oauth.register",
  status: "success",
  clientId: "client-1",
};

class RecordingSink implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(e: AuthAuditEvent): Promise<void> { this.events.push(e); }
}

class ThrowingSink implements AuditPort {
  readonly calls = { count: 0 };
  async writeAuthEvent(): Promise<void> {
    this.calls.count += 1;
    throw new Error("sink exploded");
  }
}

// A sink whose writeAuthEvent throws SYNCHRONOUSLY (not async). This still
// satisfies the AuditPort signature (a non-async function returning Promise is
// legal at runtime) — exactly the "misbehaving custom sink" class that a bare
// `sinks.map(s => s.writeAuthEvent(...))` would let escape Promise.allSettled.
class SyncThrowingSink implements AuditPort {
  readonly calls = { count: 0 };
  writeAuthEvent(): Promise<void> {
    this.calls.count += 1;
    throw new Error("sync sink exploded");
  }
}

function captureConsoleError(): { messages: string[]; restore: () => void } {
  const original = console.error;
  const messages: string[] = [];
  console.error = (...args: unknown[]) => { messages.push(args.map(String).join(" ")); };
  return { messages, restore: () => { console.error = original; } };
}

test("combineAudit: delivers to every sink", async () => {
  const a = new RecordingSink();
  const b = new RecordingSink();
  const combined = combineAudit(a, b);
  await combined.writeAuthEvent(event);
  assert.deepEqual(a.events, [event]);
  assert.deepEqual(b.events, [event]);
});

test("combineAudit: one sink rejecting does not stop the others, and never rejects itself", async () => {
  const good = new RecordingSink();
  const bad = new ThrowingSink();
  const combined = combineAudit(bad, good); // bad first to prove no short-circuit
  await assert.doesNotReject(() => combined.writeAuthEvent(event));
  assert.equal(bad.calls.count, 1, "the failing sink was still attempted");
  assert.deepEqual(good.events, [event], "the good sink still received the event");
});

test("combineAudit: ALL sinks rejecting still does not reject (fail-open)", async () => {
  const a = new ThrowingSink();
  const b = new ThrowingSink();
  const combined = combineAudit(a, b);
  await assert.doesNotReject(() => combined.writeAuthEvent(event));
  assert.equal(a.calls.count, 1);
  assert.equal(b.calls.count, 1);
});

test("combineAudit: zero sinks is a usable no-op sink", async () => {
  const combined = combineAudit();
  await assert.doesNotReject(() => combined.writeAuthEvent(event));
});

test("combineAudit: a SYNCHRONOUS-throwing sink does not reject the composite (fail-open)", async () => {
  // A sync throw inside `.map` would escape Promise.allSettled and reject the
  // composite — breaking the never-reject invariant. The good sink must still
  // receive the event.
  const good = new RecordingSink();
  const bad = new SyncThrowingSink();
  const combined = combineAudit(bad, good);
  await assert.doesNotReject(() => combined.writeAuthEvent(event));
  assert.equal(bad.calls.count, 1, "the sync-throwing sink was still attempted");
  assert.deepEqual(good.events, [event], "the good sink still received the event");
});

test("combineAudit: an undefined entry in the sinks array does not reject the composite", async () => {
  // A conditional composition root (e.g. `config.webhook ? sink : undefined`)
  // can slip an undefined into the array at runtime; accessing .writeAuthEvent on
  // it throws synchronously. The composite must absorb that and keep going.
  const good = new RecordingSink();
  const combined = combineAudit(undefined as unknown as AuditPort, good);
  await assert.doesNotReject(() => combined.writeAuthEvent(event));
  assert.deepEqual(good.events, [event]);
});

test("combineAudit: a rejected sink's reason never reaches stderr", async () => {
  // The sink's stderr line is a fixed shape (counts + event label); the rejection
  // reason — which a misbehaving custom sink could fill with anything, including
  // a copied secret — must NEVER be echoed verbatim.
  const leaky = {
    async writeAuthEvent(): Promise<void> {
      throw new Error("Bearer LEAKED-SIEM-TOKEN rt.LEAKED-REFRESH");
    },
  };
  const combined = combineAudit(leaky, new RecordingSink());
  const captured = captureConsoleError();
  try {
    await combined.writeAuthEvent(event);
  } finally {
    captured.restore();
  }
  const stderr = captured.messages.join("\n");
  assert.equal(stderr.includes("LEAKED-SIEM-TOKEN"), false, "rejection reason leaked to stderr");
  assert.equal(stderr.includes("LEAKED-REFRESH"), false, "rejection reason leaked to stderr");
  assert.ok(stderr.includes("1/2"), "the failure count was surfaced");
});
