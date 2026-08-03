import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync, existsSync, fstatSync, linkSync, lstatSync, mkdirSync,
  mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import {
  admitSqliteFile, closeSqliteAdmission, verifySqlitePathIdentity,
} from "../src/store/sqlite-open.ts";
import { openSqliteStore, SqliteStore } from "../src/store/sqlite.ts";

const UNSAFE = /sqlite: unsafe persistent state:/;

test("SQLite admission accepts only exact :memory: or a valid persistent path", async () => {
  const dir = privateDir("mcp-sso-sqlite-input-");
  const file = join(dir, "oauth.sqlite");
  try {
    const memory = openSqliteStore(":memory:");
    await memory.close();
    const openUnknown = openSqliteStore as (path: unknown) => SqliteStore;
    for (const invalid of [undefined, null, 7, {}, "", "   ", "bad\0path"]) {
      assert.throws(() => openUnknown(invalid), UNSAFE);
    }
    for (const uri of [`file:${file}?mode=rwc`, `FiLe:${file}?mode=rwc`]) {
      assert.throws(() => openSqliteStore(uri), /file: URI names are not supported/);
      assert.equal(existsSync(uri), false, "the rejected URI was not treated as a literal filename");
    }
    assert.equal(existsSync(file), false, "rejected inputs caused no filesystem write");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("SQLite admission maps an unavailable current directory to a fixed path error", {
  skip: process.platform === "win32" ? "Windows does not permit removing a process's current directory" : false,
}, () => {
  const sqliteUrl = new URL("../src/store/sqlite.ts", import.meta.url).href;
  const script = [
    `import { mkdtempSync, rmSync } from "node:fs";`,
    `import { tmpdir } from "node:os";`,
    `import { join } from "node:path";`,
    `import { openSqliteStore } from ${JSON.stringify(sqliteUrl)};`,
    `const dir = mkdtempSync(join(tmpdir(), "mcp-sso-deleted-cwd-"));`,
    `process.chdir(dir);`,
    `rmSync(dir, { recursive: true });`,
    `try { openSqliteStore("state.sqlite"); process.exit(0); }`,
    `catch (error) { process.stderr.write(String(error?.message ?? error)); process.exit(1); }`,
  ].join("\n");
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /^sqlite: unsafe persistent state: cannot resolve the database path$/);
  assert.doesNotMatch(result.stderr, /uv_cwd|ENOENT/);
});

test("SQLite admission creates 0600 state and reopens an existing private database", async () => {
  const dir = privateDir("mcp-sso-sqlite-positive-");
  const file = join(dir, "oauth.sqlite");
  try {
    const first = openSqliteStore(file);
    await first.close();
    if (process.platform !== "win32") assert.equal(lstatSync(file).mode & 0o777, 0o600);
    const before = readFileSync(file);
    const reopened = openSqliteStore(file);
    await reopened.close();
    assert.deepEqual(readFileSync(file), before, "an idempotent reopen does not rewrite the schema");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("SQLite admission rejects unsafe directories and existing 0644 state without mutation", {
  skip: process.platform === "win32" ? "POSIX mode and ownership policy has no Windows ACL equivalent" : false,
}, () => {
  const root = privateDir("mcp-sso-sqlite-permissions-");
  const unsafeDir = join(root, "unsafe");
  const unsafeAncestor = join(root, "unsafe-ancestor");
  const privateChild = join(unsafeAncestor, "private-child");
  const notDir = join(root, "not-directory");
  const missingDir = join(root, "missing");
  const file = join(root, "state.sqlite");
  try {
    mkdirSync(unsafeDir, { mode: 0o777 });
    chmodSync(unsafeDir, 0o777);
    mkdirSync(privateChild, { recursive: true, mode: 0o700 });
    chmodSync(unsafeAncestor, 0o777);
    chmodSync(privateChild, 0o700);
    writeFileSync(notDir, "not a directory", { mode: 0o600 });
    assert.throws(() => openSqliteStore(join(unsafeDir, "state.sqlite")), /inaccessible to group and other users/);
    assert.equal(existsSync(join(unsafeDir, "state.sqlite")), false, "unsafe directory rejected before creation");
    assert.throws(
      () => openSqliteStore(join(privateChild, "state.sqlite")),
      /directory ancestry is replaceable by another OS user/,
    );
    assert.equal(existsSync(join(privateChild, "state.sqlite")), false, "unsafe ancestry rejected before creation");
    assert.throws(() => openSqliteStore(join(notDir, "state.sqlite")), /not a directory/);
    assert.throws(() => openSqliteStore(join(missingDir, "state.sqlite")), /must already exist/);
    writeFileSync(file, "chosen bytes", { mode: 0o600 });
    chmodSync(file, 0o644);
    const before = readFileSync(file);
    assert.throws(() => openSqliteStore(file), /existing database file must have mode 0600/);
    assert.equal(openDescriptorCount(file), 0, "mode rejection closed the verification descriptor");
    assert.equal(lstatSync(file).mode & 0o777, 0o644, "the rejected file was not chmodded");
    assert.deepEqual(readFileSync(file), before, "the rejected file was not opened by SQLite");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("SQLite admission rejects a wrong-owner immediate directory before target creation", {
  skip: process.platform === "win32" || process.geteuid?.() === 0
    ? "requires a non-root POSIX service user so the root-owned directory has a different UID"
    : false,
}, () => {
  const target = join("/", `.mcp-sso-owner-probe-${process.pid}.sqlite`);
  assert.throws(() => openSqliteStore(target), /immediate database directory must be owned/);
  assert.equal(existsSync(target), false);
});

test("SQLite admission rejects final symlinks, symlinked directories, directories, and hard links", (t) => {
  const dir = privateDir("mcp-sso-sqlite-types-");
  const target = join(dir, "target.sqlite");
  const liveLink = join(dir, "live.sqlite");
  const dangling = join(dir, "dangling.sqlite");
  const hardLink = join(dir, "hard.sqlite");
  const realDirectory = join(dir, "real-directory");
  const directoryLink = join(dir, "directory-link");
  try {
    writeFileSync(target, "target bytes", { mode: 0o600 });
    try {
      symlinkSync(target, liveLink);
      symlinkSync(join(dir, "absent.sqlite"), dangling);
    } catch (error) {
      if (process.platform === "win32" && hasCode(error, "EPERM")) {
        t.skip("Windows file-symlink creation needs Developer Mode or elevated privilege");
        return;
      }
      throw error;
    }
    for (const path of [liveLink, dangling]) {
      assert.throws(() => openSqliteStore(path), /final path is a symlink or junction/);
    }
    assert.equal(existsSync(join(dir, "absent.sqlite")), false, "a dangling symlink target was not created");
    assert.deepEqual(readFileSync(target), Buffer.from("target bytes"));
    assert.throws(() => openSqliteStore(dir), /final path is not a regular file/);
    mkdirSync(realDirectory, { mode: 0o700 });
    try {
      symlinkSync(realDirectory, directoryLink, process.platform === "win32" ? "junction" : undefined);
    } catch (error) {
      if (process.platform === "win32" && hasCode(error, "EPERM")) {
        t.skip("Windows directory-symlink creation needs Developer Mode or elevated privilege");
        return;
      }
      throw error;
    }
    assert.throws(() => openSqliteStore(join(directoryLink, "state.sqlite")), /immediate database directory is a symlink/);
    linkSync(target, hardLink);
    assert.throws(() => openSqliteStore(target), /must have exactly one link/);
    assert.equal(lstatSync(target).nlink, 2, "rejection did not unlink either name");
    assert.deepEqual(readFileSync(hardLink), Buffer.from("target bytes"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("SQLite admission rejects a POSIX socket and device path", {
  skip: process.platform === "win32" ? "Unix-domain socket and POSIX device paths are not Windows filesystem primitives" : false,
}, async () => {
  const dir = privateDir("mcp-sso-sqlite-special-");
  const socket = join(dir, "state.sock");
  try {
    const server = createServer();
    await new Promise<void>((resolve, reject) => server.once("error", reject).listen(socket, resolve));
    try {
      assert.throws(() => openSqliteStore(socket), /final path is not a regular file/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    if (existsSync("/dev/null")) assert.throws(() => openSqliteStore("/dev/null"), UNSAFE);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("SQLite admission detects a deterministic path-identity replacement", () => {
  const dir = privateDir("mcp-sso-sqlite-identity-");
  const file = join(dir, "state.sqlite");
  const replacement = join(dir, "replacement.sqlite");
  const displaced = join(dir, "displaced.sqlite");
  writeFileSync(file, "first", { mode: 0o600 });
  writeFileSync(replacement, "second", { mode: 0o600 });
  const admission = admitSqliteFile(file);
  try {
    renameSync(file, displaced);
    renameSync(replacement, file);
    assert.throws(() => verifySqlitePathIdentity(file, admission.identity), /identity changed during open/);
  } finally {
    closeSqliteAdmission(admission.fd);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("SQLite initialization failure closes its connection and preserves fixed errors", () => {
  const dir = privateDir("mcp-sso-sqlite-init-failure-");
  const file = join(dir, "invalid.sqlite");
  const moved = join(dir, "moved.sqlite");
  const controlFile = join(dir, "control.sqlite");
  const bytes = Buffer.from("chosen non-SQLite bytes");
  try {
    if (process.platform !== "win32") {
      const control = new DatabaseSync(controlFile);
      assert.ok(openDescriptorCount(controlFile) > 0, "the FD probe observes a live DatabaseSync control");
      control.close();
      assert.equal(openDescriptorCount(controlFile), 0, "the FD probe observes the control close");
    }
    writeFileSync(file, bytes, { mode: 0o600 });
    assert.throws(
      () => openSqliteStore(file),
      /sqlite: unsafe persistent state: database initialization failed/,
    );
    assert.deepEqual(readFileSync(file), bytes, "failed initialization did not rewrite the admitted file");
    if (process.platform !== "win32") {
      assert.equal(openDescriptorCount(file), 0, "failed initialization closed DatabaseSync and admission descriptors");
    }
    renameSync(file, moved);
    assert.equal(existsSync(moved), true, "the failed path remains reusable");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("direct SqliteStore construction remains caller-owned", async () => {
  const dir = privateDir("mcp-sso-sqlite-direct-");
  const file = join(dir, "caller.sqlite");
  try {
    if (process.platform !== "win32") chmodSync(dir, 0o777);
    const db = new DatabaseSync(file);
    const store = new SqliteStore(db);
    await store.close();
    assert.equal(existsSync(file), true, "the constructor wraps a caller-opened connection");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function privateDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}

function hasCode(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error
    && (error as { code?: unknown }).code === code;
}

function openDescriptorCount(file: string): number {
  const expected = lstatSync(file, { bigint: true });
  let count = 0;
  for (const entry of readdirSync("/dev/fd")) {
    const fd = Number(entry);
    if (!Number.isInteger(fd)) continue;
    try {
      const current = fstatSync(fd, { bigint: true });
      if (current.dev === expected.dev && current.ino === expected.ino) count += 1;
    } catch { /* a descriptor may close between directory read and fstat */ }
  }
  return count;
}
