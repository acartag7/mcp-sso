// JsonlFileAudit — append-only, metadata-only auth-audit sink (contracts §13,
// §17.7). One JSON.stringify'd event per line; the file is the deployer's to
// rotate (logrotate) and retain (compliance period).
//
// Safety invariants (threat-model row 24):
//   - Log-injection-safe by construction: JSON.stringify escapes `\n`/`\r` inside
//     string fields, so a hostile `reason` can never start a fresh log line.
//   - Each event is one `fs.appendFile` call → one `write()` syscall on an
//     O_APPEND descriptor → kernel-atomic append for buffers ≤ PIPE_BUF (our
//     lines are tiny), so concurrent writers across processes never interleave
//     inside a line.
//   - Fail-open: writeAuthEvent NEVER rejects. Audit is evidence, not a gate
//     (§17.7); a full disk / renamed file / IO error surfaces on stderr and the
//     auth flow proceeds. This matches how the use-cases call us (they `await`
//     with no try/catch — verifier.ts, register.ts — so a rejecting sink would
//     turn every IO hiccup into a 500).
//   - Mode 0600 at creation; if the file already exists its existing mode is
//     kept (mode applies only at creation — a pre-existing world-readable file
//     is the deployer's responsibility, NOT fail-closed here; §17.7 specifies no
//     boot perm check for the JSONL sink, unlike quickstart §17.8).
//
// Rotation: appendFile re-resolves the path on every write, so a deployer's
// logrotate (rename + recreate, the default) is followed automatically — the
// next write lands in the new file. A held file handle would keep writing the
// renamed inode; this design does not.

import { appendFile } from "node:fs/promises";
import type { AuthAuditEvent, AuditPort } from "../ports/audit.ts";

export class JsonlFileAudit implements AuditPort {
  private readonly filePath: string;

  constructor(filePath: string) {
    if (!filePath || typeof filePath !== "string") {
      throw new TypeError("JsonlFileAudit: filePath must be a non-empty string");
    }
    this.filePath = filePath;
  }

  async writeAuthEvent(event: AuthAuditEvent): Promise<void> {
    try {
      // `undefined` fields are omitted by JSON.stringify; exactly one trailing
      // `\n` makes each event one line and the file parseable as JSONL. Built
      // INSIDE the try so a throwing toJSON / cycle / BigInt is swallowed —
      // writeAuthEvent MUST NEVER reject (§17.7; cf. WebhookAudit's full-body
      // wrap). Defense-in-depth: AuthAuditEvent is flat primitives today.
      const line = `${JSON.stringify(event)}\n`;
      // flag "a" = O_APPEND | O_WRONLY | O_CREAT; mode 0o600 applied at creation.
      await appendFile(this.filePath, line, { flag: "a", mode: 0o600 });
    } catch (error) {
      // Fail-open: never reject. No secret can appear here — the payload is
      // metadata-only and `error` is an IO message (no tokens cross this path).
      console.error(
        `[mcp-sso] audit jsonl write failed (${this.eventLabel(event)}): ${errorMessage(error)}`,
      );
    }
  }

  private eventLabel(event: AuthAuditEvent): string {
    // Avoid logging the payload; just enough to correlate a failure to an event.
    return `${event.event}/${event.status}`;
  }
}

export function createJsonlFileAudit(filePath: string): JsonlFileAudit {
  return new JsonlFileAudit(filePath);
}

function errorMessage(error: unknown): string {
  return String((error as { message?: unknown } | null)?.message ?? error);
}
