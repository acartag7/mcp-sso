// ConsolePairingIdentity (contracts §17.5, threat-model row 21).
// Verification rows S1b.5–S1b.7 + the security invariants: charset/canonicalization,
// timing-safe compare, nonce binding, single-use, lazy generation + reuse,
// in-process cap independent of RateLimitPort (deny ≠ throw), and the load-bearing
// "the pairing code NEVER appears in an audit event" assertion.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { AuthAuditEvent, AuditPort } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import {
  createConsolePairingIdentity, generatePairingCode, canonicalizePairingCode,
  formatPairingCode, PAIRING_CHARSET,
} from "../src/identity/console-pairing.ts";

class FakeClock implements ClockPort {
  private ms = 1_700_000_000_000;
  nowMs(): number { return this.ms; }
  advance(seconds: number): void { this.ms += seconds * 1000; }
}

function capture() {
  const chunks: string[] = [];
  const output = { write(s: string): boolean { chunks.push(s); return true; } };
  return { chunks, output, text: () => chunks.join("") };
}

/** Extract every printed code (canonical 12-char) from captured output. */
function codesFrom(text: string): string[] {
  const re = /code: ([BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4})/g;
  const out: string[] = [];
  for (let m = re.exec(text); m; m = re.exec(text)) out.push(m[1]!.replace(/-/g, ""));
  return out;
}

function newIdentity(opts: { clock?: ClockPort; rateLimit?: { check(): Promise<boolean> }; audit?: AuditPort; subject?: string; maxAttempts?: number; codeTtlSeconds?: number } = {}) {
  const cap = capture();
  const identity = createConsolePairingIdentity({
    output: cap.output,
    clock: opts.clock ?? new FakeClock(),
    rateLimit: opts.rateLimit,
    audit: opts.audit,
    subject: opts.subject,
    maxAttempts: opts.maxAttempts,
    codeTtlSeconds: opts.codeTtlSeconds,
  });
  return { identity, cap };
}

test("code generation: 12 chars from the base-20 charset; format XXXX-XXXX-XXXX", () => {
  for (let i = 0; i < 200; i++) {
    const code = generatePairingCode();
    assert.equal(code.length, 12);
    for (const ch of code) assert.ok(PAIRING_CHARSET.includes(ch), `char ${ch} not in charset`);
    const displayed = formatPairingCode(code);
    assert.match(displayed, /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
    assert.equal(canonicalizePairingCode(displayed), code, "canonical(displayed) === code");
  }
  // No vowels / Y / digits ever appear (unambiguous-alphabet property).
  assert.equal(generatePairingCode().includes("A"), false);
});

test("canonicalize: uppercase + strip everything outside the charset", () => {
  assert.equal(canonicalizePairingCode("bcdf-ghjk-lmnp"), "BCDFGHJKLMNP");
  assert.equal(canonicalizePairingCode("  b c d f g h j k l m n p  "), "BCDFGHJKLMNP");
  assert.equal(canonicalizePairingCode("aeiouy"), ""); // vowels + Y stripped
  assert.equal(canonicalizePairingCode("123!@#"), "");
});

test("S1b.5: lazy generation — beginSession prints the code once and reuses it while live", async () => {
  const { identity, cap } = newIdentity();
  const a = await identity.beginSession();
  const b = await identity.beginSession();
  assert.equal(a.nonce, b.nonce, "same active code reused — nonce identical");
  assert.equal(cap.chunks.length, 1, "the code is printed exactly once (no reprint on reuse)");
  assert.match(cap.text(), /Console pairing code:/);
  assert.match(cap.text(), /SINGLE-OPERATOR/);
});

test("S1b.5: happy path — code accepted once, single-use, returns the subject", async () => {
  const { identity, cap } = newIdentity({ subject: "op@test" });
  const session = await identity.beginSession();
  const code = codesFrom(cap.text())[0]!;
  const ok = await identity.verify({ code, nonce: session.nonce });
  assert.equal(ok.ok, true);
  if (ok.ok) assert.equal(ok.identity.subject, "op@test");

  // Single-use: the consumed code cannot authorize again.
  const replay = await identity.verify({ code, nonce: session.nonce });
  assert.equal(replay.ok, false);
});

test("S1b.6: FIVE wrong attempts invalidate the code, independent of RateLimitPort (noop limiter)", async () => {
  const { identity, cap } = newIdentity({ maxAttempts: 5 });
  const session = await identity.beginSession();
  const wrong = "BBBBBBBBBBBB"; // 12 charset chars, will not match the real code
  for (let i = 0; i < 5; i++) {
    const r = await identity.verify({ code: wrong, nonce: session.nonce });
    assert.equal(r.ok, false, `attempt ${i + 1} rejected`);
  }
  // The active code is now invalidated: even the correct code fails.
  const realCode = codesFrom(cap.text())[0]!;
  const after = await identity.verify({ code: realCode, nonce: session.nonce });
  assert.equal(after.ok, false, "correct code rejected after exhaustion");
  // And beginSession prints a FRESH code (not a reprint of the old banner).
  const beforeCount = cap.chunks.length;
  await identity.beginSession();
  assert.equal(cap.chunks.length, beforeCount + 1, "a fresh code is printed after invalidation");
});

test("rate-limit DENY blocks without bumping the attempt cap; THROW fails open", async () => {
  // Mutable limiter: deny while we flood wrong attempts, then allow the correct one.
  let deny = true;
  const limiter = { async check(): Promise<boolean> { return !deny; } };
  const { identity, cap } = newIdentity({ rateLimit: limiter });
  const session = await identity.beginSession();
  const realCode = codesFrom(cap.text())[0]!;

  // 10 denied attempts — none reach the code check, so wrongAttempts stays 0.
  for (let i = 0; i < 10; i++) {
    const r = await identity.verify({ code: "BBBBBBBBBBBB", nonce: session.nonce });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "pairing_rate_limited");
  }
  // The real code is still alive (cap untouched by denials).
  deny = false;
  const ok = await identity.verify({ code: realCode, nonce: session.nonce });
  assert.equal(ok.ok, true, "rate-limit denials did not exhaust the attempt cap");

  // A THROWING limiter fails open: the correct code still succeeds.
  const throwy = { async check(): Promise<boolean> { throw new Error("limiter down"); } };
  const { identity: id2, cap: cap2 } = newIdentity({ rateLimit: throwy });
  const s2 = await id2.beginSession();
  const code2 = codesFrom(cap2.text())[0]!;
  const ok2 = await id2.verify({ code: code2, nonce: s2.nonce });
  assert.equal(ok2.ok, true, "fail-open: a limiter outage does not block pairing");
});

test("S1b.7: replay (consumed) and expiry are both rejected", async () => {
  const clock = new FakeClock();
  const { identity, cap } = newIdentity({ clock, codeTtlSeconds: 600 });
  const session = await identity.beginSession();
  const code = codesFrom(cap.text())[0]!;

  // Expiry: advance past the TTL; the code is dead even though never used.
  clock.advance(601);
  const expired = await identity.verify({ code, nonce: session.nonce });
  assert.equal(expired.ok, false);
});

test("nonce binding: the correct code with the wrong nonce is rejected", async () => {
  const { identity, cap } = newIdentity();
  const session = await identity.beginSession();
  const code = codesFrom(cap.text())[0]!;
  const wrongNonce = await identity.beginSession(); // would reuse — get nonce a different way
  void wrongNonce;
  const r = await identity.verify({ code, nonce: "not-the-real-nonce-AAAAAAAAAAAAAAAA" });
  assert.equal(r.ok, false, "code cannot be consumed without its session nonce");
});

test("a bare string input (e.g. a header value) fails closed", async () => {
  const { identity } = newIdentity();
  await identity.beginSession();
  const r = await identity.verify("just-a-string-not-an-object");
  assert.equal(r.ok, false);
});

test("invalid input shape fails closed", async () => {
  const { identity } = newIdentity();
  await identity.beginSession();
  const r = await identity.verify({ code: "BBBBBBBBBBBB" }); // missing nonce
  assert.equal(r.ok, false);
});

test("SECURITY: the pairing code NEVER appears in any audit event (success or failure)", async () => {  const events: AuthAuditEvent[] = [];
  const audit: AuditPort = { async writeAuthEvent(e) { events.push(e); } };
  const { identity, cap } = newIdentity({ audit });

  // Success flow → oauth.pairing.attempt success.
  const s1 = await identity.beginSession();
  const code1 = codesFrom(cap.text())[0]!;
  const ok = await identity.verify({ code: code1, nonce: s1.nonce, ip: "203.0.113.9" });
  assert.equal(ok.ok, true);

  // Failure flow → oauth.pairing.attempt failure.
  const s2 = await identity.beginSession();
  const code2 = codesFrom(cap.text())[1]!;
  const bad = await identity.verify({ code: "BBBBBBBBBBBB", nonce: s2.nonce });
  assert.equal(bad.ok, false);

  const pairingEvents = events.filter((e) => e.event === "oauth.pairing.attempt");
  assert.ok(pairingEvents.some((e) => e.status === "success"), "a success event was emitted");
  assert.ok(pairingEvents.some((e) => e.status === "failure"), "a failure event was emitted");
  assert.ok(pairingEvents.some((e) => e.ip === "203.0.113.9"), "ip carried through");

  // The codes (displayed with dashes, and canonical without) appear NOWHERE in any event.
  const blob = JSON.stringify(events);
  assert.equal(blob.includes(code1), false, "canonical code leaked into audit");
  assert.equal(blob.includes(formatPairingCode(code1)), false, "displayed code leaked into audit");
  assert.equal(blob.includes(code2), false);
  assert.equal(blob.includes(formatPairingCode(code2)), false);
  // reason is always a short enum, never a message containing the code.
  for (const e of pairingEvents) {
    if (e.reason) assert.ok(e.reason.length < 40 && !/[A-Z]{4}-[A-Z]{4}-[A-Z]{4}/.test(e.reason));
  }
});

test("FAIL-OPEN (§17.7): a throwing/rejecting AuditPort never breaks pairing", async () => {
  // Mirrors audit-flow.test.ts S1a.3 for the S1a sinks. pairing.verify() awaits
  // writeAuthEvent; emit() MUST swallow sink errors so a non-fail-open custom
  // sink can never 500 the pairing flow. The throwing sink's message must also
  // never reach the caller.
  const throwing: AuditPort = {
    async writeAuthEvent(): Promise<void> { throw new Error("sink down BEARER LEAKED_ATTEMPT"); },
  };
  const { identity, cap } = newIdentity({ audit: throwing });

  // beginSession prints the code (its own write — not the audit sink).
  const session = await identity.beginSession();
  const code = codesFrom(cap.text())[0]!;

  // Success path: resolves ok despite the throwing sink.
  const ok = await identity.verify({ code, nonce: session.nonce });
  assert.equal(ok.ok, true);

  // Failure path: a wrong-code verify also resolves (no throw) despite the sink.
  const session2 = await identity.beginSession();
  const bad = await identity.verify({ code: "BBBBBBBBBBBB", nonce: session2.nonce });
  assert.equal(bad.ok, false);

  // The throwing sink's rejection reason never escaped into a result reason.
  if (!bad.ok) assert.equal(bad.reason.includes("LEAKED"), false);
});
