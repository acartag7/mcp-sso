// Windows skips the quickstart, standalone state-dir check, managed state-dir,
// and persistent-SQLite POSIX permission gates.
// These child-process probes preserve real production wiring while isolating
// the per-runtime one-shot signal and the process.platform override.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

const WARNING = "[mcp-sso] Windows filesystem permissions are not verified:";
const rootUrl = new URL("../src/index.ts", import.meta.url).href;
const quickstartUrl = new URL("../src/quickstart.ts", import.meta.url).href;
const sqliteUrl = new URL("../src/store/sqlite.ts", import.meta.url).href;
const stateDirUrl = new URL("../src/state-dir.ts", import.meta.url).href;

function run(script: string) {
  return spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    encoding: "utf8",
  });
}

function warningCount(stderr: string): number {
  return stderr.split(WARNING).length - 1;
}

test("quickstart emits one fixed Windows permission warning without its path", () => {
  const marker = "operator-controlled-secret-path";
  const result = run(`
    import { mkdtempSync, rmSync } from "node:fs";
    import { tmpdir } from "node:os";
    import { join } from "node:path";
    Object.defineProperty(process, "platform", { value: "win32" });
    const { loadOrCreateQuickstartSecrets } = await import(${JSON.stringify(quickstartUrl)});
    const base = mkdtempSync(join(tmpdir(), "mcp-sso-win-warning-"));
    const dir = join(base, ${JSON.stringify(marker)});
    try { await loadOrCreateQuickstartSecrets({ dir }); await loadOrCreateQuickstartSecrets({ dir }); }
    finally { rmSync(base, { recursive: true, force: true }); }
  `);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(warningCount(result.stderr), 1, result.stderr);
  assert.doesNotMatch(result.stderr, new RegExp(marker));
  assert.match(result.stderr, /private ACL-controlled directory/);
  assert.match(result.stderr, /secret manager/);
});

test("persistent SQLite emits the same warning; :memory: does not consume it", () => {
  const result = run(`
    import { chmodSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
    import { tmpdir } from "node:os";
    import { join } from "node:path";
    Object.defineProperty(process, "platform", { value: "win32" });
    const { openSqliteStore } = await import(${JSON.stringify(sqliteUrl)});
    const memory = openSqliteStore(":memory:"); await memory.close();
    const dir = mkdtempSync(join(realpathSync(tmpdir()), "mcp-sso-win-sqlite-"));
    chmodSync(dir, 0o700);
    try {
      const first = openSqliteStore(join(dir, "first.sqlite")); await first.close();
      const second = openSqliteStore(join(dir, "second.sqlite")); await second.close();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  `);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(warningCount(result.stderr), 1, result.stderr);
});

test("quickstart and persistent SQLite share one runtime-wide warning", () => {
  const result = run(`
    import { chmodSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
    import { tmpdir } from "node:os";
    import { join } from "node:path";
    Object.defineProperty(process, "platform", { value: "win32" });
    const { loadOrCreateQuickstartSecrets } = await import(${JSON.stringify(quickstartUrl)});
    const { openSqliteStore } = await import(${JSON.stringify(sqliteUrl)});
    const base = mkdtempSync(join(realpathSync(tmpdir()), "mcp-sso-win-shared-"));
    const quickstart = join(base, "quickstart");
    try {
      await loadOrCreateQuickstartSecrets({ dir: quickstart });
      const store = openSqliteStore(join(quickstart, "state.sqlite")); await store.close();
    } finally { rmSync(base, { recursive: true, force: true }); }
  `);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(warningCount(result.stderr), 1, result.stderr);
});

test("POSIX use stays silent and a throwing warning transport cannot break Windows boot", () => {
  const positive = run(`
    import { mkdtempSync, rmSync } from "node:fs";
    import { tmpdir } from "node:os";
    import { join } from "node:path";
    const { loadOrCreateQuickstartSecrets } = await import(${JSON.stringify(quickstartUrl)});
    const base = mkdtempSync(join(tmpdir(), "mcp-sso-posix-warning-"));
    try { await loadOrCreateQuickstartSecrets({ dir: join(base, "state") }); }
    finally { rmSync(base, { recursive: true, force: true }); }
  `);
  assert.equal(positive.status, 0, positive.stderr);
  assert.equal(warningCount(positive.stderr), 0, positive.stderr);

  const contained = run(`
    import { mkdtempSync, rmSync } from "node:fs";
    import { tmpdir } from "node:os";
    import { join } from "node:path";
    Object.defineProperty(process, "platform", { value: "win32" });
    console.warn = () => { throw new Error("logging unavailable"); };
    const { loadOrCreateQuickstartSecrets } = await import(${JSON.stringify(quickstartUrl)});
    const base = mkdtempSync(join(tmpdir(), "mcp-sso-win-contained-"));
    try { await loadOrCreateQuickstartSecrets({ dir: join(base, "state") }); }
    finally { rmSync(base, { recursive: true, force: true }); }
  `);
  assert.equal(contained.status, 0, contained.stderr);
});

test("ensureStateDir emits the same one-shot warning without its path", () => {
  // §17.8 parity: this is the third state-dir path. A consumer that manages its
  // own directory and keeps database state elsewhere reaches neither the
  // quickstart nor the SQLite warning, so without this call it is silently
  // unprotected on Windows — the gap review caught on the first two-path fix.
  const marker = "operator-controlled-state-path";
  const result = run(`
    import { mkdtempSync, rmSync } from "node:fs";
    import { tmpdir } from "node:os";
    import { join } from "node:path";
    Object.defineProperty(process, "platform", { value: "win32" });
    const { ensureStateDir } = await import(${JSON.stringify(stateDirUrl)});
    const base = mkdtempSync(join(tmpdir(), "mcp-sso-win-statedir-"));
    const dir = join(base, ${JSON.stringify(marker)});
    try { await ensureStateDir(dir); await ensureStateDir(dir); }
    finally { rmSync(base, { recursive: true, force: true }); }
  `);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(warningCount(result.stderr), 1, result.stderr);
  assert.doesNotMatch(result.stderr, new RegExp(marker));
  assert.match(result.stderr, /managed state directories/);
});

test("root-exported assertRealDir emits the shared Windows warning without its path", () => {
  const marker = "operator-controlled-standalone-path";
  const result = run(`
    import { chmodSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
    import { tmpdir } from "node:os";
    import { join } from "node:path";
    Object.defineProperty(process, "platform", { value: "win32" });
    const { assertRealDir } = await import(${JSON.stringify(rootUrl)});
    const base = mkdtempSync(join(tmpdir(), "mcp-sso-win-real-dir-"));
    const dir = join(base, ${JSON.stringify(marker)});
    try {
      mkdirSync(dir); chmodSync(dir, 0o777);
      await assertRealDir(dir); await assertRealDir(dir);
    } finally { rmSync(base, { recursive: true, force: true }); }
  `);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(warningCount(result.stderr), 1, result.stderr);
  assert.doesNotMatch(result.stderr, new RegExp(marker));
});

test("Windows quickstart fallback rejects a non-regular secrets path", () => {
  const result = run(`
    import { chmodSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
    import { tmpdir } from "node:os";
    import { join } from "node:path";
    Object.defineProperty(process, "platform", { value: "win32" });
    const { loadOrCreateQuickstartSecrets } = await import(${JSON.stringify(quickstartUrl)});
    const base = mkdtempSync(join(tmpdir(), "mcp-sso-win-regular-file-"));
    const dir = join(base, "state");
    mkdirSync(dir); chmodSync(dir, 0o777); writeFileSync(join(dir, ".gitignore"), "*\\n");
    mkdirSync(join(dir, "secrets.json"));
    try {
      await loadOrCreateQuickstartSecrets({ dir });
      throw new Error("non-regular secrets path was accepted");
    } catch (error) {
      if (!(error instanceof Error) || !error.message.includes("is not a regular file")) throw error;
    } finally { rmSync(base, { recursive: true, force: true }); }
  `);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(warningCount(result.stderr), 1, result.stderr);
});

test("ensureStateDir stays silent on POSIX, where the gates are enforced", () => {
  const result = run(`
    import { mkdtempSync, rmSync } from "node:fs";
    import { tmpdir } from "node:os";
    import { join } from "node:path";
    const { ensureStateDir } = await import(${JSON.stringify(stateDirUrl)});
    const base = mkdtempSync(join(tmpdir(), "mcp-sso-posix-statedir-"));
    try { await ensureStateDir(join(base, "state")); }
    finally { rmSync(base, { recursive: true, force: true }); }
  `);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(warningCount(result.stderr), 0, result.stderr);
});
