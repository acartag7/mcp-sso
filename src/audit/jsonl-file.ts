// JsonlFileAudit — append-only, metadata-only auth-audit sink (contracts §13,
// §17.7). One JSON.stringify'd event per line; the file is the deployer's to
// rotate (logrotate) and retain (compliance period).
//
// Safety invariants (threat-model row 24):
//   - Log-injection-safe by construction: JSON.stringify escapes `\n`/`\r` inside
//     string fields, so a hostile `reason` can never start a fresh log line.
//   - Each event opens the final component with O_NOFOLLOW, checks the opened
//     descriptor is a regular file, then writes the whole encoded line through
//     that same O_APPEND descriptor. There is no path check followed by a second,
//     unsafe open. O_NOFOLLOW cannot identify a hard-linked regular file; that
//     deliberately remains the deployer's parent-directory/host-policy boundary.
//   - Calls to one sink instance are serialized. O_APPEND protects each write
//     syscall, not a multi-syscall short-write retry, so a queue keeps another
//     event from landing between chunks of the current JSONL record.
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
// Rotation: opening the final path on every write means a deployer's logrotate
// (rename + recreate, the default) is followed automatically — the next write
// lands in the new file. A held file handle would keep writing the renamed inode;
// this design does not.

import { open, constants as fsc, type FileHandle } from "node:fs/promises";
import type { AuthAuditEvent, AuditPort } from "../ports/audit.ts";

// O_NOFOLLOW rejects the final-component symlink. If Node cannot expose a native
// no-follow flag, this sink must not fall back to lstat() then open(): a swap can
// land the append in the link target. It drops the event fail-open instead.
const rawNoFollow: number | undefined = (fsc as { O_NOFOLLOW?: number }).O_NOFOLLOW;
const O_NOFOLLOW: number | undefined = rawNoFollow && rawNoFollow !== 0 ? rawNoFollow : undefined;
// O_NONBLOCK stops open() blocking on a FIFO/special file at the audit path (a
// plain O_WRONLY open on a FIFO waits for a reader — that would hang the awaited
// writeAuthEvent and break fail-open). POSIX; 0 where unavailable.
const O_NONBLOCK: number = (fsc as { O_NONBLOCK?: number }).O_NONBLOCK ?? 0;
const APPEND_FLAGS: number = fsc.O_WRONLY | fsc.O_APPEND | fsc.O_CREAT | O_NONBLOCK;
const NO_FOLLOW_UNAVAILABLE = "no_follow_unavailable";
const PARTIAL_ROLLBACK_UNVERIFIED = "partial_write_rollback_unverified";
// Only operating-system error codes are useful without exposing arbitrary
// filesystem paths, thrown JSON errors, or event-derived text. Anything else is
// a fixed reason. This set is closed so a hostile object cannot smuggle a secret
// through a fabricated `.code` property.
const SAFE_ERROR_CODES = new Set([
  "EACCES", "EAGAIN", "EBADF", "EEXIST", "EFBIG", "EINTR", "EINVAL", "EIO",
  "EISDIR", "ELOOP", "EMFILE", "ENFILE", "ENOSPC", "ENOTDIR", "ENXIO", "EPERM", "EROFS", "ETXTBSY",
]);

export type JsonlFileAuditDisableReason = typeof PARTIAL_ROLLBACK_UNVERIFIED;
export interface JsonlFileAuditOptions {
  onDisable?: (reason: JsonlFileAuditDisableReason) => void | Promise<void>;
}

export class JsonlFileAudit implements AuditPort {
  private readonly filePath: string;
  private readonly onDisable: JsonlFileAuditOptions["onDisable"];
  private appendTail: Promise<void> = Promise.resolve();
  private appendDisabled = false;

  constructor(filePath: string, options: JsonlFileAuditOptions = {}) {
    if (!filePath || typeof filePath !== "string") {
      throw new TypeError("JsonlFileAudit: filePath must be a non-empty string");
    }
    if (options === null || typeof options !== "object" || Array.isArray(options)) {
      throw new TypeError("JsonlFileAudit: options must be an object");
    }
    const onDisable = options.onDisable;
    if (onDisable !== undefined && typeof onDisable !== "function") {
      throw new TypeError("JsonlFileAudit: onDisable must be a function");
    }
    this.filePath = filePath;
    this.onDisable = onDisable;
  }

  async writeAuthEvent(event: AuthAuditEvent): Promise<void> {
    const append = this.appendTail
      .then(() => this.appendEvent(event))
      // Keep the queue moving and the port fail-open even if a future regression
      // makes appendEvent throw outside its own failure boundary.
      .catch((error: unknown) => { this.reportFailure(error); });
    this.appendTail = append;
    await append;
  }

  private async appendEvent(event: AuthAuditEvent): Promise<void> {
    if (this.appendDisabled) return;
    try {
      // `undefined` fields are omitted by JSON.stringify; exactly one trailing
      // `\n` makes each event one line and the file parseable as JSONL. Built
      // INSIDE the try so a throwing toJSON / cycle / BigInt is swallowed —
      // writeAuthEvent MUST NEVER reject (§17.7; cf. WebhookAudit's full-body
      // wrap). Defense-in-depth: AuthAuditEvent is flat primitives today.
      const line = `${JSON.stringify(event)}\n`;
      if (O_NOFOLLOW === undefined) throw new Error(NO_FOLLOW_UNAVAILABLE);
      // Open+fstat+write+close per event (rotation-robust: the path is re-resolved
      // each write, so a logrotate rename+recreate is followed). The no-follow
      // open, descriptor validation, and write are one descriptor-bound operation.
      const fh = await open(this.filePath, APPEND_FLAGS | O_NOFOLLOW, 0o600);
      try {
        const st = await fh.stat();
        if (!st.isFile()) throw new Error("audit target is not a regular file");
        try {
          await writeCompleteLine(fh, Buffer.from(line, "utf8"));
        } catch (error) {
          if (error instanceof PartialAuditWriteError
            && !await rollbackPartialLine(fh, st.size, error.bytesWritten)) {
            this.disableAppends(PARTIAL_ROLLBACK_UNVERIFIED);
          }
          throw error;
        }
      } finally {
        await fh.close();
      }
    } catch (error) {
      // Fail-open: never reject. The error message is NOT trusted to be
      // secret-free (an fs error includes the configured path; a future field's
      // toJSON could put anything in an Error.message), so only an allowlisted
      // OS error code reaches stderr (threat-model #14). Never include the event,
      // its fields, the configured path, or a raw thrown-error message.
      this.reportFailure(error);
    }
  }

  private safeError(error: unknown): string {
    try {
      const code = (error as { code?: unknown } | null)?.code;
      return typeof code === "string" && SAFE_ERROR_CODES.has(code) ? code : "audit_write_failed";
    } catch {
      return "audit_write_failed";
    }
  }

  private reportFailure(error: unknown): void {
    try {
      console.error(`[mcp-sso] audit jsonl write failed: ${this.safeError(error)}`);
    } catch {
      // A failed console/logging transport is still audit infrastructure. It must
      // not turn an otherwise fail-open audit write into an authentication error.
    }
  }

  private disableAppends(reason: JsonlFileAuditDisableReason): void {
    if (this.appendDisabled) return;
    this.appendDisabled = true;
    try {
      console.error(`[mcp-sso] audit jsonl disabled: ${reason}`);
    } catch {
      // A broken stderr transport cannot suppress the independent callback.
    }
    try {
      void Promise.resolve(this.onDisable?.(reason)).catch(() => {});
    } catch {
      // Operator notification is fail-open and one-shot even when its hook fails.
    }
  }
}

class PartialAuditWriteError extends Error {
  readonly bytesWritten: number;

  constructor(bytesWritten: number) {
    super("partial audit JSONL write");
    this.bytesWritten = bytesWritten;
  }
}

/** Complete the exact encoded line or report how much of it was appended. */
async function writeCompleteLine(fh: FileHandle, line: Buffer): Promise<void> {
  let offset = 0;
  try {
    while (offset < line.length) {
      const { bytesWritten } = await fh.write(line, offset, line.length - offset);
      if (!Number.isSafeInteger(bytesWritten) || bytesWritten <= 0) {
        throw new Error("incomplete audit JSONL write");
      }
      offset += bytesWritten;
    }
  } catch (error) {
    if (offset > 0) throw new PartialAuditWriteError(offset);
    throw error;
  }
}

/** Roll back only our verified tail. An uncoordinated writer makes that unsafe,
 *  so stop this instance rather than risk joining a later record to a fragment. */
async function rollbackPartialLine(fh: FileHandle, initialSize: number, bytesWritten: number): Promise<boolean> {
  try {
    const afterWrite = await fh.stat();
    if (afterWrite.size !== initialSize + bytesWritten) return false;
    await fh.truncate(initialSize);
    return (await fh.stat()).size === initialSize;
  } catch {
    return false;
  }
}

export function createJsonlFileAudit(filePath: string, options?: JsonlFileAuditOptions): JsonlFileAudit {
  return new JsonlFileAudit(filePath, options);
}
