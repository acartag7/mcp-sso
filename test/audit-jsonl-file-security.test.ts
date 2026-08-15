// JsonlFileAudit hostile final-path coverage. These tests exercise the exact
// descriptor boundary: O_NOFOLLOW must reject a symlink before it can redirect a
// write, and fstat().isFile() must reject special targets after opening them.

import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { constants as fsc } from "node:fs";
import { mkdir, mkdtemp, open, readFile, rename, rm, stat, symlink, type FileHandle, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  createJsonlFileAudit, JsonlFileAudit, type JsonlFileAuditOptions,
} from "../src/audit/jsonl-file.ts";
import type { AuthAuditEvent } from "../src/ports/audit.ts";

const hasNoFollow = typeof (fsc as { O_NOFOLLOW?: number }).O_NOFOLLOW === "number" && fsc.O_NOFOLLOW !== 0;
const event: AuthAuditEvent = {
  occurredAt: "2026-08-03T12:00:00.000Z",
  event: "auth.request",
  status: "success",
  clientId: "client-1",
};

type FileHandleWrite = (this: FileHandle, data: Uint8Array | string, offset?: number, length?: number, position?: number | null) => Promise<{ bytesWritten: number; buffer: Uint8Array | string }>;
type FileHandleStat = (this: FileHandle) => Promise<{ size: number }>;

function captureConsoleError(): { messages: string[]; restore: () => void } {
  const original = console.error;
  const messages: string[] = [];
  console.error = (...args: unknown[]) => { messages.push(args.map(String).join(" ")); };
  return { messages, restore: () => { console.error = original; } };
}

async function withDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-audit-secure-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

test("JsonlFileAudit: a final-component symlink never receives audit bytes", async () => {
  if (!hasNoFollow || process.platform === "win32") return;
  await withDir(async (dir) => {
    const victim = join(dir, "victim.jsonl");
    const path = join(dir, "audit.jsonl");
    await writeFile(victim, "victim-before\n");
    await symlink(victim, path);
    const captured = captureConsoleError();
    try {
      await assert.doesNotReject(() => new JsonlFileAudit(path).writeAuthEvent(event));
    } finally {
      captured.restore();
    }
    assert.equal(await readFile(victim, "utf8"), "victim-before\n", "symlink target was modified");
    assert.ok(captured.messages.join("\n").includes("audit jsonl write failed"));
  });
});

test("JsonlFileAudit: a swap to a symlink between events cannot redirect the second append", async () => {
  if (!hasNoFollow || process.platform === "win32") return;
  await withDir(async (dir) => {
    const path = join(dir, "audit.jsonl");
    const victim = join(dir, "victim.jsonl");
    const sink = new JsonlFileAudit(path);
    await sink.writeAuthEvent(event);
    await rm(path);
    await writeFile(victim, "victim-before\n");
    await symlink(victim, path);

    await assert.doesNotReject(() => sink.writeAuthEvent({ ...event, status: "failure" }));

    assert.equal(await readFile(victim, "utf8"), "victim-before\n", "swapped symlink redirected an audit write");
  });
});

test("JsonlFileAudit: a dangling final-component symlink neither writes nor creates its target", async () => {
  if (!hasNoFollow || process.platform === "win32") return;
  await withDir(async (dir) => {
    const path = join(dir, "audit.jsonl");
    const danglingTarget = join(dir, "must-not-exist.jsonl");
    await symlink(danglingTarget, path);

    await assert.doesNotReject(() => new JsonlFileAudit(path).writeAuthEvent(event));

    assert.equal(await exists(danglingTarget), false, "dangling link target was created");
  });
});

test("JsonlFileAudit: a directory target is rejected fail-open", async () => {
  if (!hasNoFollow) return;
  await withDir(async (dir) => {
    const directory = join(dir, "audit-directory");
    await mkdir(directory);
    const captured = captureConsoleError();
    try {
      await assert.doesNotReject(() => new JsonlFileAudit(directory).writeAuthEvent(event));
    } finally {
      captured.restore();
    }
    const stderr = captured.messages.join("\n");
    assert.ok(stderr.includes("audit jsonl write failed"), "special target rejection was not surfaced");
  });
});

test("JsonlFileAudit: a character-device target is rejected after descriptor validation", async () => {
  if (!hasNoFollow || process.platform === "win32") return;
  const nullDevice = await stat("/dev/null");
  if (!nullDevice.isCharacterDevice()) return;
  const captured = captureConsoleError();
  try {
    await assert.doesNotReject(() => new JsonlFileAudit("/dev/null").writeAuthEvent(event));
  } finally {
    captured.restore();
  }
  assert.ok(captured.messages.join("\n").includes("audit jsonl write failed"), "character-device target was not rejected by fstat().isFile()");
});

test("JsonlFileAudit: a Unix socket target is rejected without blocking", async () => {
  if (!hasNoFollow || process.platform === "win32") return;
  await withDir(async (dir) => {
    const socketPath = join(dir, "audit.sock");
    const server = createServer();
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, () => {
        server.off("error", reject);
        resolve();
      });
    });
    try {
      const result = await Promise.race([
        new JsonlFileAudit(socketPath).writeAuthEvent(event).then(() => "resolved" as const),
        new Promise<"HUNG">((resolve) => setTimeout(() => resolve("HUNG"), 2000)),
      ]);
      assert.equal(result, "resolved", "socket target blocked the audit sink");
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});

test("JsonlFileAudit: rename-and-recreate rotation moves the next complete line to the replacement", async () => {
  if (!hasNoFollow) return;
  await withDir(async (dir) => {
    const path = join(dir, "audit.jsonl");
    const rotated = join(dir, "audit.jsonl.1");
    const sink = new JsonlFileAudit(path);
    await sink.writeAuthEvent(event);
    await rename(path, rotated);
    await writeFile(path, "", { mode: 0o600 });
    await sink.writeAuthEvent({ ...event, status: "failure" });

    const oldLine = JSON.parse((await readFile(rotated, "utf8")).trim()) as AuthAuditEvent;
    const newLine = JSON.parse((await readFile(path, "utf8")).trim()) as AuthAuditEvent;
    assert.equal(oldLine.status, "success");
    assert.equal(newLine.status, "failure");
  });
});

test("JsonlFileAudit: a failing sink does not reject or expose its path or event payload on stderr", async () => {
  await withDir(async (dir) => {
    const blocker = join(dir, "not-a-directory");
    const pathSecret = "path-secret-7";
    const payloadSecret = "event-payload-secret";
    await writeFile(blocker, "x");
    const path = join(blocker, `audit-${pathSecret}.jsonl`);
    const captured = captureConsoleError();
    try {
      await assert.doesNotReject(() => new JsonlFileAudit(path).writeAuthEvent({ ...event, reason: payloadSecret }));
    } finally {
      captured.restore();
    }
    const stderr = captured.messages.join("\n");
    assert.ok(stderr.includes("audit jsonl write failed"), "failure diagnostic missing");
    assert.equal(stderr.includes(path), false, "configured path leaked to stderr");
    assert.equal(stderr.includes(pathSecret), false, "short secret in configured path leaked to stderr");
    assert.equal(stderr.includes(payloadSecret), false, "event payload leaked to stderr");
  });
});

test("JsonlFileAudit: a hostile serialization error cannot leak event-derived text on stderr", async () => {
  const payloadSecret = "serialization-event-payload-secret";
  const captured = captureConsoleError();
  try {
    await assert.doesNotReject(() => new JsonlFileAudit("audit.jsonl").writeAuthEvent({
      toJSON() { throw new Error(payloadSecret); },
    } as unknown as AuthAuditEvent));
  } finally {
    captured.restore();
  }
  const stderr = captured.messages.join("\n");
  assert.ok(stderr.includes("audit jsonl write failed"), "serialization failure diagnostic missing");
  assert.equal(stderr.includes(payloadSecret), false, "serialization error leaked event-derived text");
});

test("JsonlFileAudit: a throwing stderr transport cannot break fail-open", async () => {
  await withDir(async (dir) => {
    const blocker = join(dir, "not-a-directory");
    await writeFile(blocker, "x");
    const original = console.error;
    console.error = () => { throw new Error("stderr unavailable"); };
    try {
      await assert.doesNotReject(() => new JsonlFileAudit(join(blocker, "audit.jsonl")).writeAuthEvent(event));
    } finally {
      console.error = original;
    }
  });
});

test("JsonlFileAudit: retries a controlled short write until one JSONL record is complete", async () => {
  if (!hasNoFollow) return;
  await withDir(async (dir) => {
    const path = join(dir, "audit.jsonl");
    await writeFile(path, "");
    const probe = await open(path, "r");
    const prototype = Object.getPrototypeOf(probe) as { write: FileHandleWrite };
    await probe.close();
    const original = prototype.write;
    let writeCalls = 0;
    prototype.write = async function (data, offset, length, position) {
      writeCalls += 1;
      if (writeCalls === 1) {
        if (typeof data === "string") {
          const firstByte = Buffer.from(data, "utf8").subarray(0, 1);
          return original.call(this, firstByte, 0, firstByte.length, position);
        }
        return original.call(this, data, offset, 1, position);
      }
      return original.call(this, data, offset, length, position);
    };
    try {
      await new JsonlFileAudit(path).writeAuthEvent(event);
      assert.equal(writeCalls, 2, "a short write was not retried");
      assert.deepEqual(JSON.parse(await readFile(path, "utf8")), event);
    } finally {
      prototype.write = original;
    }
  });
});

test("JsonlFileAudit: rolls back a partial line when its short-write retry fails", async () => {
  if (!hasNoFollow) return;
  await withDir(async (dir) => {
    const path = join(dir, "audit.jsonl");
    await writeFile(path, "");
    const probe = await open(path, "r");
    const prototype = Object.getPrototypeOf(probe) as { write: FileHandleWrite };
    await probe.close();
    const original = prototype.write;
    let writeCalls = 0;
    prototype.write = async function (data, offset, length, position) {
      writeCalls += 1;
      if (writeCalls === 1) return original.call(this, data, offset, 1, position);
      if (writeCalls === 2) {
        const error = Object.assign(new Error("retry failed"), { code: "ENOSPC" });
        throw error;
      }
      return original.call(this, data, offset, length, position);
    };
    try {
      let disableCalls = 0;
      const sink = new JsonlFileAudit(path, { onDisable: () => { disableCalls += 1; } });
      await assert.doesNotReject(() => sink.writeAuthEvent({ ...event, clientId: "partial" }));
      await assert.doesNotReject(() => sink.writeAuthEvent({ ...event, clientId: "complete" }));
      const lines = (await readFile(path, "utf8")).trim().split("\n");
      assert.equal(lines.length, 1, "the partial prefix was not rolled back");
      assert.equal((JSON.parse(lines[0]!) as AuthAuditEvent).clientId, "complete");
      assert.equal(disableCalls, 0, "a verified rollback must not disable the sink");
    } finally {
      prototype.write = original;
    }
  });
});

test("JsonlFileAudit: drops later events when a partial-line rollback is unverified", async () => {
  if (!hasNoFollow) return;
  await withDir(async (dir) => {
    const path = join(dir, "audit.jsonl");
    await writeFile(path, "");
    const probe = await open(path, "r");
    const prototype = Object.getPrototypeOf(probe) as {
      stat: FileHandleStat;
      write: FileHandleWrite;
    };
    await probe.close();
    const originalStat = prototype.stat;
    const originalWrite = prototype.write;
    let statCalls = 0;
    let writeCalls = 0;
    prototype.stat = async function () {
      const result = await originalStat.call(this);
      statCalls += 1;
      return statCalls === 2 ? { ...result, size: result.size + 1 } as typeof result : result;
    };
    prototype.write = async function (data, offset, length, position) {
      writeCalls += 1;
      if (writeCalls === 1) return originalWrite.call(this, data, offset, 1, position);
      if (writeCalls === 2) throw new Error("retry failed");
      return originalWrite.call(this, data, offset, length, position);
    };
    const disableReasons: string[] = [];
    let replacementCalls = 0;
    const options: JsonlFileAuditOptions = {
      async onDisable(reason: string) {
        disableReasons.push(reason);
        throw new Error("operator hook failed");
      },
    };
    const captured = captureConsoleError();
    try {
      const sink = createJsonlFileAudit(path, options);
      options.onDisable = () => { replacementCalls += 1; };
      await assert.doesNotReject(() => sink.writeAuthEvent({ ...event, clientId: "event-field-first" }));
      const afterPartial = await readFile(path, "utf8");
      await assert.doesNotReject(() => sink.writeAuthEvent({ ...event, clientId: "event-field-later" }));
      assert.equal(await readFile(path, "utf8"), afterPartial, "a later event extended the partial record");
      assert.equal(writeCalls, 2, "a disabled sink performed later file work");
      assert.deepEqual(disableReasons, ["partial_write_rollback_unverified"]);
      assert.equal(replacementCalls, 0, "the constructor did not snapshot the callback");
    } finally {
      captured.restore();
      prototype.stat = originalStat;
      prototype.write = originalWrite;
    }
    const stderr = captured.messages.join("\n");
    assert.equal(
      captured.messages.filter((message) => message.includes(
        "[mcp-sso] audit jsonl disabled: partial_write_rollback_unverified",
      )).length,
      1,
      "the permanent transition did not emit exactly one alertable diagnostic",
    );
    assert.equal(stderr.includes(path), false);
    assert.equal(stderr.includes("event-field-first"), false);
    assert.equal(stderr.includes("event-field-later"), false);
    assert.equal(stderr.includes("operator hook failed"), false);
  });
});

test("JsonlFileAudit: concurrent short writes cannot splice one sink instance's JSONL records", async () => {
  if (!hasNoFollow) return;
  await withDir(async (dir) => {
    const path = join(dir, "audit.jsonl");
    await writeFile(path, "");
    const probe = await open(path, "r");
    const prototype = Object.getPrototypeOf(probe) as { write: FileHandleWrite };
    await probe.close();
    const original = prototype.write;
    let releaseFirstWrite: () => void = () => {};
    const firstWriteReleased = new Promise<void>((resolve) => { releaseFirstWrite = resolve; });
    let signalFirstWrite: () => void = () => {};
    const firstWriteStarted = new Promise<void>((resolve) => { signalFirstWrite = resolve; });
    let signalSecondWrite: () => void = () => {};
    const secondWriteStarted = new Promise<void>((resolve) => { signalSecondWrite = resolve; });
    let writeCalls = 0;
    prototype.write = async function (buffer, offset, length, position) {
      writeCalls += 1;
      if (writeCalls === 1) {
        const result = await original.call(this, buffer, offset, 1, position);
        signalFirstWrite();
        await firstWriteReleased;
        return result;
      }
      if (writeCalls === 2) signalSecondWrite();
      return original.call(this, buffer, offset, length, position);
    };
    try {
      const sink = new JsonlFileAudit(path);
      const first = sink.writeAuthEvent({ ...event, clientId: "first" });
      await firstWriteStarted;
      const second = sink.writeAuthEvent({ ...event, clientId: "second" });
      const secondWriteState = await Promise.race([
        secondWriteStarted.then(() => "entered"),
        new Promise<"blocked">((resolve) => { setTimeout(() => resolve("blocked"), 100); }),
      ]);
      assert.equal(secondWriteState, "blocked", "second event wrote before the first short write completed");
      releaseFirstWrite();
      await Promise.all([first, second]);
      const lines = (await readFile(path, "utf8")).trim().split("\n").map((line) => JSON.parse(line) as AuthAuditEvent);
      assert.deepEqual(lines.map((line) => line.clientId), ["first", "second"]);
    } finally {
      releaseFirstWrite();
      prototype.write = original;
    }
  });
});

test("JsonlFileAudit: FIFO target remains nonblocking", async () => {
  if (!hasNoFollow || process.platform === "win32") return;
  await withDir(async (dir) => {
    const fifo = join(dir, "audit.fifo");
    execSync(`mkfifo '${fifo}'`);
    const result = await Promise.race([
      new JsonlFileAudit(fifo).writeAuthEvent(event).then(() => "resolved" as const),
      new Promise<"HUNG">((resolve) => setTimeout(() => resolve("HUNG"), 2000)),
    ]);
    assert.equal(result, "resolved", "FIFO target blocked the audit sink");
  });
});
