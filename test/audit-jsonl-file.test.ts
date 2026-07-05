// JsonlFileAudit — proves the §17.7 contract: one valid JSON line per event,
// file created 0600, log-injection-safe (hostile newlines in a field cannot
// start a fresh line), and fail-open (an unwritable path never rejects, so the
// auth flow is never blocked by an IO error).

import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { JsonlFileAudit } from "../src/audit/jsonl-file.ts";
import type { AuthAuditEvent } from "../src/ports/audit.ts";

function captureConsoleError(): { messages: string[]; restore: () => void } {
  const original = console.error;
  const messages: string[] = [];
  console.error = (...args: unknown[]) => { messages.push(args.map(String).join(" ")); };
  return { messages, restore: () => { console.error = original; } };
}

let counter = 0;
function tmpFile(dir: string): string {
  counter += 1;
  return join(dir, `audit-${process.pid}-${Date.now()}-${counter}.jsonl`);
}

async function withDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-audit-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const baseEvent: AuthAuditEvent = {
  occurredAt: "2026-07-05T12:00:00.000Z",
  event: "oauth.token.authorization_code",
  status: "success",
  clientId: "client-1",
  subject: "agent@test",
  resource: "https://api.test/mcp",
  scopes: ["mcp:read"],
  redirectHost: "client.test",
  reason: undefined,
  ip: "203.0.113.7",
};

test("JsonlFileAudit: writes one valid JSON line per event with trailing newline", async () => {
  await withDir(async (dir) => {
    const path = tmpFile(dir);
    const sink = new JsonlFileAudit(path);
    await sink.writeAuthEvent({ ...baseEvent });
    await sink.writeAuthEvent({ ...baseEvent, event: "oauth.token.refresh", status: "failure" });

    const raw = await readFile(path, "utf8");
    const lines = raw.split("\n");
    // Two payloads + the empty string after the final trailing newline.
    assert.equal(lines.length, 3, "exactly two lines, each terminated by \\n");
    assert.equal(lines[2], "", "file ends with a single trailing newline");
    const first = JSON.parse(lines[0]!);
    const second = JSON.parse(lines[1]!);
    assert.equal(first.event, "oauth.token.authorization_code");
    assert.equal(first.ip, "203.0.113.7"); // ip field round-trips
    assert.equal(second.event, "oauth.token.refresh");
    assert.equal(second.status, "failure");
  });
});

test("JsonlFileAudit: file is created mode 0600", async () => {
  await withDir(async (dir) => {
    const path = tmpFile(dir);
    const sink = new JsonlFileAudit(path);
    await sink.writeAuthEvent({ ...baseEvent });
    const s = await stat(path);
    // POSIX permission bits only (mask off type).
    assert.equal(s.mode & 0o777, 0o600, "audit file must be created 0600");
  });
});

test("JsonlFileAudit: hostile newlines in a field never split a log line (no injection)", async () => {
  await withDir(async (dir) => {
    const path = tmpFile(dir);
    const sink = new JsonlFileAudit(path);
    // A CR/LF-laden reason is the classic log-injection vector: if it reached
    // the file raw, "inject" would start a second line masquerading as a real
    // event. JSON.stringify must escape both.
    await sink.writeAuthEvent({
      ...baseEvent,
      reason: "evil\r\ninject-fake-event",
    });
    const raw = await readFile(path, "utf8");
    assert.equal(raw.includes("\ninject-fake-event"), false, "raw newline must not start a new line");
    assert.equal(raw.includes("\rinject-fake-event"), false, "raw CR must not leak");
    const lines = raw.split("\n");
    assert.equal(lines.length, 2); // one payload + trailing-empty
    // And the round-tripped value still carries the original bytes intact.
    const parsed = JSON.parse(lines[0]!);
    assert.equal(parsed.reason, "evil\r\ninject-fake-event");
  });
});

test("JsonlFileAudit: never rejects (fail-open) on an unwritable path", async () => {
  await withDir(async (dir) => {
    // A path inside a path component that is itself a file (not a dir) cannot be
    // opened/created — appendFile rejects. The sink must swallow it.
    const blockingFile = join(dir, "iamfile");
    await writeFile(blockingFile, "x");
    const sink = new JsonlFileAudit(join(blockingFile, "audit.jsonl"));
    await assert.doesNotReject(() => sink.writeAuthEvent({ ...baseEvent }));
  });
});

test("JsonlFileAudit: stderr from an IO failure never leaks a secret-shaped string", async () => {
  await withDir(async (dir) => {
    const blockingFile = join(dir, "iamfile");
    await writeFile(blockingFile, "x");
    // A long opaque token in the filename stands in for any secret-shaped
    // string an error message might carry (the fs error includes the full
    // configured path). Redaction must scrub it before it reaches stderr.
    const secret = "RTSECRET_" + "A".repeat(48);
    const sink = new JsonlFileAudit(join(blockingFile, `audit-${secret}.jsonl`));
    const captured = captureConsoleError();
    try {
      await sink.writeAuthEvent({ ...baseEvent }); // ENOTDIR -> fail-open
    } finally {
      captured.restore();
    }
    const stderr = captured.messages.join("\n");
    assert.equal(stderr.includes(secret), false, "secret-shaped path component leaked to stderr");
    assert.equal(stderr.includes("A".repeat(48)), false, "long opaque run leaked to stderr");
    assert.ok(stderr.length > 0, "the IO failure was still surfaced");
  });
});

test("JsonlFileAudit: never rejects even if JSON.stringify throws (fail-open defense-in-depth)", async () => {
  await withDir(async (dir) => {
    const path = tmpFile(dir);
    const sink = new JsonlFileAudit(path);
    // A circular value makes JSON.stringify throw SYNCHRONOUSLY before any IO.
    // The sink must swallow it — writeAuthEvent MUST NEVER reject (the use-cases
    // await it with no try/catch). AuthAuditEvent is flat primitives today, so
    // this is a regression lock: a future field carrying a cycle/BigInt/throwing
    // toJSON cannot turn an audit write into an auth 500.
    const circular: unknown = { event: "auth.request", status: "success", occurredAt: "x" };
    (circular as { self?: unknown }).self = circular;
    await assert.doesNotReject(() => sink.writeAuthEvent(circular as AuthAuditEvent));
  });
});

test("JsonlFileAudit: constructor rejects a non-string / empty filePath", () => {
  assert.throws(() => new JsonlFileAudit(""));
  // @ts-expect-error — runtime guard against a non-string
  assert.throws(() => new JsonlFileAudit(undefined));
});

test("JsonlFileAudit: a FIFO at the audit path does not hang (open nonblocking → fail-open)", async () => {
  // open(O_WRONLY) on a FIFO blocks until a reader appears; without O_NONBLOCK the
  // awaited writeAuthEvent would hang the auth flow. O_NONBLOCK makes open return
  // (ENXIO, no reader) and the fail-open catch resolves writeAuthEvent normally.
  if (process.platform === "win32") return;
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-fifo-audit-"));
  try {
    const fifo = join(dir, "audit.fifo");
    execSync(`mkfifo '${fifo}'`);
    const sink = new JsonlFileAudit(fifo);
    const result = await Promise.race([
      sink.writeAuthEvent({ occurredAt: "2026-07-06T00:00:00.000Z", event: "auth.request", status: "success" }).then(() => "resolved" as const),
      new Promise<"HUNG">((r) => setTimeout(() => r("HUNG"), 2000)),
    ]);
    assert.equal(result, "resolved", "writeAuthEvent must resolve (fail-open), not hang on a FIFO");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
