// ConsolePairingIdentity (contracts §17.5, threat-model row 21) — a zero-IdP
// `IdentityPort` for SINGLE-OPERATOR deployments: a one-time code is printed to
// stderr and pasted at the authorize step; reading the process's stderr IS the
// trust boundary.
//
// Security: 12-char base-20 code (~51.86 bits — the WHOLE gate, not a secondary
// check), CSPRNG rejection sampling, lazy generation, ONE active code per process
// (reused while live), single-use, expiry + maxAttempts invalidation, session-
// nonce binding, timing-safe compare (length-prechecked), in-process attempt cap
// independent of RateLimitPort (pairing:<ip> hook adds defense-in-depth, fail-open
// on limiter error). Audit `oauth.pairing.attempt` reason is ALWAYS an enum — the
// 12-char code is below the 32-char redactor in src/audit/util.ts, so it must
// NEVER appear in an AuthAuditEvent. It doesn't.
// NON-GOAL (banner): shared-log pipelines extend the boundary — use a real IdP.

import { randomBytes } from "node:crypto";
import type { ClockPort } from "../ports/clock.ts";
import { SystemClock } from "../ports/clock.ts";
import type { AuditPort } from "../ports/audit.ts";
import { noopAudit } from "../ports/audit.ts";
import type { RateLimitPort } from "../ports/rate-limit.ts";
import { noopRateLimit } from "../ports/rate-limit.ts";
import type { IdentityClaims, IdentityPort, IdentityResult } from "../ports/identity.ts";
import { snapshotOwnDataRecord } from "../own-property.ts";
import {
  asVerifyInput, canonicalizePairingCode, formatPairingCode, generatePairingCode,
  positiveIntegerOption, timingSafeStringEqual,
} from "./console-pairing-internals.ts";

export {
  canonicalizePairingCode, formatPairingCode, generatePairingCode, PAIRING_CHARSET,
} from "./console-pairing-internals.ts";

export interface ConsolePairingOptions {
  /** Verified subject minted on a successful pairing. Default "console-operator". */
  subject?: string;
  /** Code lifetime in seconds. Default 600 (§17.5). */
  codeTtlSeconds?: number;
  /** Wrong submissions before the active code is invalidated. Default 5. */
  maxAttempts?: number;
  /** Where the code + banner are printed. Default process.stderr. */
  output?: { write(chunk: string): unknown };
  clock?: ClockPort;
  rateLimit?: RateLimitPort;
  audit?: AuditPort;
}

/** A live pairing session: the form nonce + the code's expiry. */
export interface PairingSession {
  nonce: string;
  expiresAt: string;
}

/** Shape passed to `verify` by the host's authorize handler. */
export interface ConsolePairingVerifyInput {
  code: string;
  nonce: string;
  ip?: string;
}

interface ActiveCode {
  code: string;
  nonce: string;
  expiresAtMs: number;
  wrongAttempts: number;
}

export interface ConsolePairingIdentity extends IdentityPort {
  /** Ensure a pairing session is active (generate + print on first need, reuse
   *  while live). Returns the form nonce + expiry. Single-flight: concurrent
   *  callers share one generation. */
  beginSession(): Promise<PairingSession>;
  verify(input: ConsolePairingVerifyInput | unknown): Promise<IdentityResult>;
}

export function createConsolePairingIdentity(opts: ConsolePairingOptions = {}): ConsolePairingIdentity {
  const snapshot = snapshotOwnDataRecord(opts);
  if (snapshot === null) throw new TypeError("console pairing options must be a data object");
  const subjectValue = snapshot.subject;
  if (subjectValue !== undefined && (typeof subjectValue !== "string" || subjectValue.length === 0)) {
    throw new TypeError("subject must be a non-empty string");
  }
  const subject = subjectValue ?? "console-operator";
  const codeTtlSeconds = positiveIntegerOption(snapshot.codeTtlSeconds, 600, "codeTtlSeconds");
  const maxAttempts = positiveIntegerOption(snapshot.maxAttempts, 5, "maxAttempts");
  const output = (snapshot.output as ConsolePairingOptions["output"]) ?? process.stderr;
  const clock = (snapshot.clock as ClockPort | undefined) ?? new SystemClock();
  const rateLimit = (snapshot.rateLimit as RateLimitPort | undefined) ?? noopRateLimit;
  const audit = (snapshot.audit as AuditPort | undefined) ?? noopAudit;

  // Process-memory only — NEVER persisted. Restart = clean slate (fail-closed).
  let active: ActiveCode | null = null;
  // Single-flight token: set before the first await so concurrent callers share one generation.
  let generating: Promise<PairingSession> | null = null;

  const identity: ConsolePairingIdentity = {
    async beginSession(): Promise<PairingSession> {
      if (generating) return generating; // reuse an in-flight generation
      const reuse = reusableSession();
      if (reuse) return reuse; // active + live + under cap → do NOT reprint
      generating = generateFresh();
      try {
        return await generating;
      } finally {
        generating = null;
      }
    },

    async verify(input: ConsolePairingVerifyInput | unknown): Promise<IdentityResult> {
      // A bare string (e.g. a header value) → code with no nonce → fails the nonce check.
      const { code: rawCode, nonce: rawNonce, ip } = asVerifyInput(input);
      if (rawCode === undefined || rawNonce === undefined) {
        await emit("failure", "invalid_input", undefined, ip);
        return { ok: false, reason: "pairing_invalid_input" };
      }

      // Defense-in-depth rate-limit hook. THROW ⇒ fail-open (matches bridge.guard());
      // DENY ⇒ block WITHOUT bumping wrongAttempts (the two controls are independent).
      let allowed = true;
      try {
        allowed = await rateLimit.check(`pairing:${ip ?? "unknown"}`);
      } catch {
        allowed = true;
      }
      if (!allowed) {
        await emit("failure", "rate_limited", undefined, ip);
        return { ok: false, reason: "pairing_rate_limited" };
      }

      if (!active) {
        await emit("failure", "no_active_code", undefined, ip);
        return { ok: false, reason: "pairing_no_active_code" };
      }
      if (clock.nowMs() >= active.expiresAtMs) {
        active = null;
        await emit("failure", "expired", undefined, ip);
        return { ok: false, reason: "pairing_expired" };
      }

      const canonical = canonicalizePairingCode(rawCode);
      // Both compares run; a single generic reason is returned so the response
      // never reveals whether the code or the nonce failed.
      const codeOk = timingSafeStringEqual(canonical, active.code);
      const nonceOk = timingSafeStringEqual(rawNonce, active.nonce);

      if (codeOk && nonceOk) {
        active = null; // single-use: consumed on success
        await emit("success", undefined, subject, ip);
        return { ok: true, identity: { subject } };
      }

      // Mismatch (code or nonce). Bump the cap; invalidate if exhausted.
      active.wrongAttempts += 1;
      const exhausted = active.wrongAttempts >= maxAttempts;
      if (exhausted) active = null; // next beginSession() prints a fresh code
      await emit("failure", exhausted ? "attempts_exhausted" : "code_mismatch", undefined, ip);
      return { ok: false, reason: "pairing_wrong_code" };
    },
  };

  function reusableSession(): PairingSession | null {
    if (!active) return null;
    if (clock.nowMs() >= active.expiresAtMs) return null;
    if (active.wrongAttempts >= maxAttempts) return null;
    return { nonce: active.nonce, expiresAt: new Date(active.expiresAtMs).toISOString() };
  }

  async function generateFresh(): Promise<PairingSession> {
    const code = generatePairingCode();
    const nonce = randomBytes(18).toString("base64url");
    const expiresAtMs = clock.nowMs() + codeTtlSeconds * 1000;
    // Print BEFORE `active`: a write failure (sync throw OR async reject) must prevent publishing.
    await printBanner(code, expiresAtMs);
    active = { code, nonce, expiresAtMs, wrongAttempts: 0 };
    return { nonce, expiresAt: new Date(expiresAtMs).toISOString() };
  }

  // output.write may be async/rejecting; awaiting observes it so the caller fails closed. Prints code + §17.5 boundary.
  async function printBanner(code: string, expiresAtMs: number): Promise<void> {
    const expiry = new Date(expiresAtMs).toISOString();
    await output.write(
      `[mcp-sso] Console pairing code: ${formatPairingCode(code)}  (expires ${expiry})\n` +
      `[mcp-sso] Console pairing is for SINGLE-OPERATOR / private-console deployments only.\n` +
      `[mcp-sso] Anyone who can read this log is the operator for the code's lifetime.\n`,
    );
  }

  // Audit `oauth.pairing.attempt` — reason is ALWAYS an enum literal (never code/nonce);
  // fail-open (never rejects, §17.7); awaited so the event orders with the response.
  async function emit(status: "success" | "failure", reason: string | undefined, subj: string | undefined, ip?: string): Promise<void> {
    try {
      await audit.writeAuthEvent({
        occurredAt: new Date(clock.nowMs()).toISOString(),
        event: "oauth.pairing.attempt",
        status,
        subject: subj,
        ip,
        reason,
      });
    } catch {
      // a sink failure must never block pairing (§17.7 fail-open)
    }
  }

  return identity;
}
