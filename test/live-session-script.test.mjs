import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  appendFileSync, chmodSync, copyFileSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync,
  statSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  acquireSessionLock, buildFlows, classifyClient, outcomeOf, readAudit, readPrivateJson, writeResults,
} from "../scripts/live/session-support.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const executable = (path, body) => { writeFileSync(path, body); chmodSync(path, 0o700); };

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "mcp-sso-session-"));
  const repo = join(root, "repo");
  const live = join(repo, "scripts/live");
  const bin = join(root, "bin");
  mkdirSync(live, { recursive: true });
  mkdirSync(bin);
  copyFileSync(join(ROOT, "session.mjs"), join(repo, "session.mjs"));
  for (const file of ["session.mjs", "session-support.mjs"]) copyFileSync(join(ROOT, "scripts/live", file), join(live, file));
  executable(join(live, "serve.sh"), `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$SERVE_LOG"
[[ "\${MCP_SSO_SESSION_PARENT_FD-}" == "4" ]] || exit 91
PARENT_WATCH_PID=""
cleanup() {
  trap - EXIT INT TERM
  if [[ -n "$PARENT_WATCH_PID" ]]; then kill "$PARENT_WATCH_PID" 2>/dev/null || true; wait "$PARENT_WATCH_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT
if [[ "\${FAKE_SERVE_STATUS:-0}" == "0" && "\${MCP_SSO_SESSION_READY_FD-}" == "3" ]]; then
  case "\${FAKE_READY_MARKER-}" in
    bad) printf 'not-ready\n' >&3 ;;
    none) : ;;
    *) printf 'ready\n' >&3 ;;
  esac
  exec 3>&-
fi
if [[ "\${FAKE_SERVE_WAIT-}" == "true" ]]; then
  (
    trap - EXIT INT TERM
    while IFS= read -r -u 4; do :; done
    printf parent-gone > "$PARENT_GONE_FILE"
    kill -TERM "$$" 2>/dev/null || true
  ) 3>&- &
  PARENT_WATCH_PID=$!
  trap 'exit 130' INT
  trap 'printf terminated > "$SERVE_TERMINATED_FILE"; exit 143' TERM
  printf '%s' "$$" > "$SERVE_PID_FILE"
  printf started > "$STARTED_FILE"
  while true; do sleep 0.1; done
fi
exit "\${FAKE_SERVE_STATUS:-0}"
`);
  const cli = `#!/usr/bin/env bash
tool="\${0##*/}"
if [[ "$1" == "--version" ]]; then printf '%s 1.2.3\n' "$tool"; exit 0; fi
printf '%s %s\n' "$tool" "$*" >> "$CLIENT_LOG"
target="$tool:$3"
if [[ "$target" == "\${ABSENT_TARGET-}" ]]; then printf 'No MCP server named %s\n' "$3" >&2; exit 1; fi
if [[ "$target" == "\${FAIL_TARGET-}" ]]; then exit 9; fi
`;
  executable(join(bin, "claude"), cli);
  executable(join(bin, "codex"), cli);
  writeFileSync(join(repo, ".gitignore"), ".live-state/\n");
  for (const args of [
    ["init", "-q"], ["config", "user.email", "fixture@example.test"], ["config", "user.name", "Fixture"],
    ["add", "."], ["commit", "-qm", "fixture"],
  ]) assert.equal(spawnSync("git", args, { cwd: repo }).status, 0);
  const env = {
    ...process.env, PATH: `${bin}:${process.env.PATH}`, SERVE_LOG: join(root, "serve.log"), CLIENT_LOG: join(root, "client.log"),
    STARTED_FILE: join(root, "started"), PARENT_GONE_FILE: join(root, "parent-gone"),
    SERVE_PID_FILE: join(root, "serve-pid"), SERVE_TERMINATED_FILE: join(root, "serve-terminated"),
  };
  return { root, repo, live, env, serveLog: env.SERVE_LOG, clientLog: env.CLIENT_LOG };
}

function waitForFile(path) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 5_000;
    const poll = () => {
      if (existsSync(path)) resolve();
      else if (Date.now() >= deadline) reject(new Error(`timed out waiting for ${path}`));
      else setTimeout(poll, 10);
    };
    poll();
  });
}

function waitForProcessExit(pid) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 10_000;
    const poll = () => {
      try { process.kill(pid, 0); } catch { resolve(); return; }
      if (Date.now() >= deadline) reject(new Error(`timed out waiting for process ${pid} to exit`));
      else setTimeout(poll, 10);
    };
    poll();
  });
}

function waitForReadySession(path) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 5_000;
    const poll = () => {
      try {
        if (JSON.parse(readFileSync(path, "utf8")).status === "ready") { resolve(); return; }
      } catch { /* the state is absent or between writes */ }
      if (Date.now() >= deadline) reject(new Error(`timed out waiting for ready state in ${path}`));
      else setTimeout(poll, 10);
    };
    poll();
  });
}

function waitForOutput(child, pattern) {
  return new Promise((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => reject(new Error(`timed out waiting for ${pattern}`)), 5_000);
    child.stdout.on("data", (chunk) => {
      output += chunk;
      if (pattern.test(output)) { clearTimeout(timer); resolve(output); }
    });
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("exit", (code) => {
      if (!pattern.test(output)) { clearTimeout(timer); reject(new Error(`watch exited ${code}: ${output}`)); }
    });
  });
}

function run(f, args, extraEnv = {}) {
  return spawnSync(process.execPath, [join(f.repo, "session.mjs"), ...args], {
    cwd: f.repo, env: { ...f.env, ...extraEnv }, encoding: "utf8", timeout: 20_000,
  });
}

const lines = (path) => existsSync(path) ? readFileSync(path, "utf8").trim().split("\n").filter(Boolean) : [];
const audit = (clientId, withRequest = true, started = Date.now() + 1_000) => {
  const at = (offset) => new Date(started + offset).toISOString();
  return [
    { occurredAt: at(0), event: "oauth.cimd.fetch", status: "success", clientId },
    { occurredAt: at(1), event: "identity.verify", status: "success" },
    { occurredAt: at(2), event: "oauth.authorize.prepare", status: "success", clientId, redirectHost: "http://localhost:49152/callback" },
    { occurredAt: at(3), event: "oauth.authorize.approve", status: "success", clientId },
    { occurredAt: at(4), event: "oauth.token.authorization_code", status: "success", clientId },
    ...(withRequest ? [{ occurredAt: at(5), event: "auth.request", status: "success", clientId }] : []),
  ];
};

test("session serve delegates to serve.sh and cleans only the selected fixed entries", () => {
  const f = fixture();
  try {
    const result = run(f, ["serve", "google"]);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(lines(f.serveLog), ["google"]);
    assert.deepEqual(lines(f.clientLog), [
      "claude mcp remove mcp-sso-live-google", "codex mcp remove mcp-sso-live-google",
    ]);
    const state = JSON.parse(readFileSync(join(f.repo, ".live-state/session.json"), "utf8"));
    assert.deepEqual(state.legs, ["google"]);
    assert.equal(state.mode, "stored");
    assert.equal(state.status, "ready");
    assert.equal(state.clean, true);
    assert.equal(statSync(join(f.repo, ".live-state")).mode & 0o077, 0);
    assert.equal(statSync(join(f.repo, ".live-state/session.json")).mode & 0o077, 0);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("session serve preserves a serve failure and still cleans every selected client", () => {
  const f = fixture();
  try {
    const result = run(f, ["serve", "entra"], { FAKE_SERVE_STATUS: "23", FAIL_TARGET: "claude:mcp-sso-live-entra" });
    assert.equal(result.status, 23, result.stderr);
    assert.deepEqual(lines(f.clientLog), [
      "claude mcp remove mcp-sso-live-entra", "codex mcp remove mcp-sso-live-entra",
    ]);
    assert.equal(existsSync(join(f.repo, ".live-state/session.json")), false);
    const watch = run(f, ["watch", "--once"]);
    assert.equal(watch.status, 1);
    assert.match(watch.stderr, /run session\.mjs serve before watch/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("session serve rejects malformed and missing readiness markers and leaves no usable state", () => {
  for (const marker of ["bad", "none"]) {
    const f = fixture();
    try {
      const result = run(f, ["serve", "google"], { FAKE_READY_MARKER: marker, FAKE_SERVE_WAIT: "true" });
      assert.equal(result.status, 1, `${marker}: ${result.stderr}`);
      assert.equal(existsSync(join(f.repo, ".live-state/session.json")), false);
      assert.equal(run(f, ["watch", "--once"]).status, 1);
    } finally { rmSync(f.root, { recursive: true, force: true }); }
  }
});

test("Ctrl-C reaches serve.sh and then cleans the selected client entries", async () => {
  const f = fixture();
  try {
    const child = spawn(process.execPath, [join(f.repo, "session.mjs"), "serve", "cloudflare_access"], {
      cwd: f.repo, env: { ...f.env, FAKE_SERVE_WAIT: "true" }, stdio: "ignore",
    });
    await waitForFile(f.env.STARTED_FILE);
    await waitForReadySession(join(f.repo, ".live-state/session.json"));
    process.kill(child.pid, "SIGINT");
    const status = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("session.mjs did not stop after Ctrl-C")), 10_000);
      child.once("error", reject);
      child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
    });
    assert.equal(status, 130);
    assert.deepEqual(lines(f.clientLog), [
      "claude mcp remove mcp-sso-live-cloudflare_access", "codex mcp remove mcp-sso-live-cloudflare_access",
    ]);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("a killed session wrapper closes its lifeline and stops serve.sh", async () => {
  const f = fixture();
  let servePid;
  try {
    const child = spawn(process.execPath, [join(f.repo, "session.mjs"), "serve", "google"], {
      cwd: f.repo, env: { ...f.env, FAKE_SERVE_WAIT: "true" }, stdio: "ignore",
    });
    await waitForReadySession(join(f.repo, ".live-state/session.json"));
    servePid = Number(readFileSync(f.env.SERVE_PID_FILE, "utf8"));
    process.kill(child.pid, "SIGKILL");
    await new Promise((resolve) => { child.once("exit", resolve); });
    await waitForFile(f.env.PARENT_GONE_FILE);
    await waitForFile(f.env.SERVE_TERMINATED_FILE);
    await waitForProcessExit(servePid);
    assert.equal(existsSync(join(f.repo, ".live-state/session.lock")), true);
    assert.equal(run(f, ["cleanup"]).status, 0);
    assert.equal(lines(f.clientLog).length, 6);
    assert.equal(existsSync(join(f.repo, ".live-state/session.lock")), false);
  } finally {
    if (servePid) try { process.kill(-servePid, "SIGKILL"); } catch { /* already gone */ }
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("one active serve owns the session state and cleanup targets", async () => {
  const f = fixture();
  let child;
  try {
    child = spawn(process.execPath, [join(f.repo, "session.mjs"), "serve", "google"], {
      cwd: f.repo, env: { ...f.env, FAKE_SERVE_WAIT: "true" }, stdio: "ignore",
    });
    const statePath = join(f.repo, ".live-state/session.json");
    const lockPath = join(f.repo, ".live-state/session.lock");
    await waitForReadySession(statePath);
    const state = readFileSync(statePath, "utf8");

    const second = run(f, ["serve", "entra"]);
    assert.equal(second.status, 1);
    assert.match(second.stderr, /another live session is active/);
    const cleanup = run(f, ["cleanup"]);
    assert.equal(cleanup.status, 1);
    assert.match(cleanup.stderr, /another live session is active/);
    assert.deepEqual(lines(f.serveLog), ["google"]);
    assert.equal(existsSync(f.clientLog), false);
    assert.equal(readFileSync(statePath, "utf8"), state);
    assert.equal(existsSync(lockPath), true);
    process.kill(child.pid, "SIGINT");
    const status = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("session.mjs did not stop after Ctrl-C")), 10_000);
      child.once("error", reject);
      child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
    });
    assert.equal(status, 130);
    assert.deepEqual(lines(f.clientLog), [
      "claude mcp remove mcp-sso-live-google", "codex mcp remove mcp-sso-live-google",
    ]);
    assert.equal(existsSync(lockPath), false);
  } finally {
    if (child?.exitCode === null) {
      child.kill("SIGKILL");
      await new Promise((resolve) => { child.once("exit", resolve); });
    }
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("serve rejects malformed and untrusted lock files before any side effect", () => {
  for (const variant of ["missing-field", "extra-field", "wrong-pid", "wrong-nonce", "active", "hard-link", "mode", "symlink", "directory-mode"]) {
    const f = fixture();
    try {
      const stateDir = join(f.repo, ".live-state");
      const lockPath = join(stateDir, "session.lock");
      mkdirSync(stateDir, { mode: 0o700 });
      if (variant === "missing-field") writeFileSync(lockPath, '{"version":1}\n', { mode: 0o600 });
      if (variant === "extra-field") writeFileSync(lockPath, `${JSON.stringify({
        version: 1, pid: process.pid, nonce: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", extra: true,
      })}\n`, { mode: 0o600 });
      if (variant === "wrong-pid") writeFileSync(lockPath, `${JSON.stringify({
        version: 1, pid: "1", nonce: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      })}\n`, { mode: 0o600 });
      if (variant === "wrong-nonce") writeFileSync(lockPath, `${JSON.stringify({
        version: 1, pid: process.pid, nonce: "not-a-nonce",
      })}\n`, { mode: 0o600 });
      if (variant === "active") writeFileSync(lockPath, `${JSON.stringify({
        version: 1, pid: process.pid, nonce: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      })}\n`, { mode: 0o600 });
      if (variant === "hard-link") {
        const original = join(f.root, "original-lock");
        writeFileSync(original, `${JSON.stringify({
          version: 1, pid: process.pid, nonce: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        })}\n`, { mode: 0o600 });
        linkSync(original, lockPath);
      }
      if (variant === "mode") {
        writeFileSync(lockPath, `${JSON.stringify({
          version: 1, pid: process.pid, nonce: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        })}\n`, { mode: 0o644 });
      }
      if (variant === "symlink") {
        const target = join(f.root, "lock-target");
        writeFileSync(target, `${JSON.stringify({
          version: 1, pid: process.pid, nonce: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        })}\n`, { mode: 0o600 });
        symlinkSync(target, lockPath);
      }
      if (variant === "directory-mode") chmodSync(stateDir, 0o755);
      const result = run(f, ["serve", "google"]);
      assert.equal(result.status, 1, variant);
      assert.equal(existsSync(f.serveLog), false, variant);
      assert.equal(existsSync(f.clientLog), false, variant);
      assert.equal(existsSync(join(stateDir, "session.json")), false, variant);
    } finally { rmSync(f.root, { recursive: true, force: true }); }
  }
});

test("lock release refuses to remove a replacement with another nonce", () => {
  const root = mkdtempSync(join(tmpdir(), "mcp-sso-session-lock-release-"));
  const path = join(root, "session.lock");
  try {
    chmodSync(root, 0o700);
    const release = acquireSessionLock(path);
    const record = JSON.parse(readFileSync(path, "utf8"));
    writeFileSync(path, `${JSON.stringify({
      ...record, nonce: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    })}\n`);
    assert.throws(release, /lock ownership changed/);
    assert.equal(existsSync(path), true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("stale lock recovery rechecks the exact record before unlinking", () => {
  const root = mkdtempSync(join(tmpdir(), "mcp-sso-session-lock-stale-"));
  const path = join(root, "session.lock");
  const originalKill = process.kill;
  try {
    chmodSync(root, 0o700);
    writeFileSync(path, `${JSON.stringify({
      version: 1, pid: 2_147_483_647, nonce: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    })}\n`, { mode: 0o600 });
    let calls = 0;
    process.kill = (pid, signal) => {
      calls += 1;
      if (calls === 1) writeFileSync(path, `${JSON.stringify({
        version: 1, pid: process.pid, nonce: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      })}\n`);
      return originalKill.call(process, pid, signal);
    };
    assert.throws(() => acquireSessionLock(path), /stale live-session lock changed/);
    const replacement = JSON.parse(readFileSync(path, "utf8"));
    assert.equal(replacement.pid, process.pid);
    assert.equal(replacement.nonce, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
  } finally {
    process.kill = originalKill;
    rmSync(root, { recursive: true, force: true });
  }
});

test("concurrent stale lock recovery admits only one owner", async () => {
  const root = mkdtempSync(join(tmpdir(), "mcp-sso-session-lock-race-"));
  const path = join(root, "session.lock");
  const runner = join(root, "runner.mjs");
  const start = join(root, "start");
  const releaseSignal = join(root, "release");
  const acquired = join(root, "acquired");
  const preload = join(root, "interleave.cjs");
  const children = [];
  try {
    chmodSync(root, 0o700);
    writeFileSync(path, `${JSON.stringify({
      version: 1, pid: 2_147_483_647, nonce: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    })}\n`, { mode: 0o600 });
    writeFileSync(preload, `
const fs = require("node:fs");
const { syncBuiltinESMExports } = require("node:module");
const lockPath = ${JSON.stringify(path)};
const releasePath = ${JSON.stringify(releaseSignal)};
const arrived = (role) => ${JSON.stringify(join(root, "unlink."))} + role;
const opened = ${JSON.stringify(join(root, "a-opened"))};
const originalOpenSync = fs.openSync;
const originalUnlinkSync = fs.unlinkSync;
const waitFor = (target) => {
  const deadline = Date.now() + 5_000;
  while (!fs.existsSync(target)) {
    if (Date.now() >= deadline) throw new Error(\`timed out waiting for \${target}\`);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
  }
};
let intercepted = false;
fs.unlinkSync = function (target, ...args) {
  if (!intercepted && String(target) === lockPath && !fs.existsSync(releasePath)) {
    intercepted = true;
    if (!fs.existsSync(\`\${lockPath}.recovery\`)) {
      fs.writeFileSync(arrived(process.env.RACE_ROLE), "arrived");
      if (process.env.RACE_ROLE === "a") waitFor(arrived("b"));
      else waitFor(opened);
    }
  }
  return originalUnlinkSync.call(this, target, ...args);
};
fs.openSync = function (target, flags, ...args) {
  const fd = originalOpenSync.call(this, target, flags, ...args);
  if (process.env.RACE_ROLE === "a" && String(target) === lockPath
    && fs.existsSync(arrived("a")) && fs.existsSync(arrived("b"))) fs.writeFileSync(opened, "opened");
  return fd;
};
syncBuiltinESMExports();
`);
    writeFileSync(runner, `
import { appendFileSync, existsSync, writeFileSync } from "node:fs";
import { acquireSessionLock } from ${JSON.stringify(new URL("../scripts/live/session-support.mjs", import.meta.url).href)};
writeFileSync(\`${join(root, "ready.")}\${process.pid}\`, "ready");
while (!existsSync(${JSON.stringify(start)})) await new Promise((resolve) => setTimeout(resolve, 5));
try {
  const release = acquireSessionLock(${JSON.stringify(path)});
  appendFileSync(${JSON.stringify(acquired)}, \`\${process.pid}\\n\`);
  while (!existsSync(${JSON.stringify(releaseSignal)})) await new Promise((resolve) => setTimeout(resolve, 5));
  release();
} catch (error) {
  process.stderr.write(\`\${error.message}\\n\`);
  process.exitCode = 1;
}
`);
    children.push(
      spawn(process.execPath, [runner], { env: { ...process.env, NODE_OPTIONS: `--require=${preload}`, RACE_ROLE: "a" } }),
      spawn(process.execPath, [runner], { env: { ...process.env, NODE_OPTIONS: `--require=${preload}`, RACE_ROLE: "b" } }),
    );
    await Promise.all(children.map((child) => waitForFile(join(root, `ready.${child.pid}`))));
    writeFileSync(start, "start");
    await waitForFile(acquired);
    await new Promise((resolve) => { setTimeout(resolve, 100); });
    writeFileSync(releaseSignal, "release");
    const codes = await Promise.all(children.map((child) => child.exitCode !== null
      ? Promise.resolve(child.exitCode)
      : new Promise((resolve, reject) => {
        child.once("error", reject);
        child.once("exit", resolve);
      })));
    assert.deepEqual(codes.sort(), [0, 1]);
    assert.equal(lines(acquired).length, 1);
    assert.equal(existsSync(`${path}.recovery`), false);
  } finally {
    for (const child of children) if (child.exitCode === null) child.kill("SIGKILL");
    rmSync(root, { recursive: true, force: true });
  }
});

test("session rejects unknown and repeated legs before any side effect", () => {
  for (const args of [["serve", "other"], ["serve", "google", "google"]]) {
    const f = fixture();
    try {
      const result = run(f, args);
      assert.equal(result.status, 1);
      assert.equal(existsSync(f.serveLog), false);
      assert.equal(existsSync(f.clientLog), false);
      assert.equal(existsSync(join(f.repo, ".live-state")), false);
    } finally { rmSync(f.root, { recursive: true, force: true }); }
  }
});

test("session rejects an invalid DCR mode before any side effect", () => {
  const f = fixture();
  try {
    const result = run(f, ["serve", "google"], { MCP_SSO_DCR_MODE: "other" });
    assert.equal(result.status, 1);
    assert.equal(existsSync(f.serveLog), false);
    assert.equal(existsSync(f.clientLog), false);
    assert.equal(existsSync(join(f.repo, ".live-state")), false);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("session refuses a hard-linked state file before truncating its other name", () => {
  const f = fixture();
  try {
    const stateDir = join(f.repo, ".live-state");
    const original = join(f.root, "original-state");
    mkdirSync(stateDir, { mode: 0o700 });
    writeFileSync(original, "keep\n", { mode: 0o600 });
    linkSync(original, join(stateDir, "session.json"));
    assert.equal(run(f, ["serve", "google"]).status, 1);
    assert.equal(readFileSync(original, "utf8"), "keep\n");
    assert.equal(existsSync(f.serveLog), false);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("explicit cleanup attempts all six fixed targets and continues after failure", () => {
  const f = fixture();
  try {
    const result = run(f, ["cleanup"], { FAIL_TARGET: "claude:mcp-sso-live-entra", ABSENT_TARGET: "claude:mcp-sso-live-google" });
    assert.equal(result.status, 1);
    assert.deepEqual(lines(f.clientLog), [
      "claude mcp remove mcp-sso-live-cloudflare_access", "codex mcp remove mcp-sso-live-cloudflare_access",
      "claude mcp remove mcp-sso-live-entra", "codex mcp remove mcp-sso-live-entra",
      "claude mcp remove mcp-sso-live-google", "codex mcp remove mcp-sso-live-google",
    ]);
    assert.match(result.stdout, /cleaned claude MCP entry mcp-sso-live-google/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("one-shot watch records PASS only after a protected request", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const leg = join(f.repo, ".live-state/google");
    mkdirSync(leg, { recursive: true });
    writeFileSync(join(leg, "audit.jsonl"), `${audit("https://claude.ai/oauth-client").map(JSON.stringify).join("\n")}\n`);
    const result = run(f, ["watch", "--all", "--once"]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /PASS A3 google Claude Code/);
    const saved = JSON.parse(readFileSync(join(f.repo, ".live-state/session-results.jsonl"), "utf8"));
    assert.equal(saved.verdict, "PASS");
    assert.equal(saved.row, "A3");
    assert.equal(saved.toolCalls, 1);
    assert.equal(saved.clientVersion, "claude 1.2.3");
    assert.equal(saved.clean, true);
    assert.match(saved.commit, /^[0-9a-f]{40}$/);
    assert.equal(statSync(join(f.repo, ".live-state/session-results.jsonl")).mode & 0o077, 0);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("one-shot watch records a token without a protected request as TOKEN_ONLY", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const leg = join(f.repo, ".live-state/google");
    mkdirSync(leg, { recursive: true });
    writeFileSync(join(leg, "audit.jsonl"), `${audit("https://chatgpt.com/oauth-client", false).map(JSON.stringify).join("\n")}\n`);
    const result = run(f, ["watch", "--all", "--once"]);
    assert.equal(result.status, 0, result.stderr);
    const saved = JSON.parse(readFileSync(join(f.repo, ".live-state/session-results.jsonl"), "utf8"));
    assert.equal(saved.verdict, "TOKEN_ONLY");
    assert.equal(saved.toolCalls, 0);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("Codex DCR attribution is explicit and limited to its generated loopback client id", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const leg = join(f.repo, ".live-state/google");
    mkdirSync(leg, { recursive: true });
    const clientId = `mcpdc_${"a".repeat(32)}`;
    writeFileSync(join(leg, "audit.jsonl"), `${audit(clientId).map(JSON.stringify).join("\n")}\n`);

    assert.equal(run(f, ["watch", "--all", "--once"]).status, 0);
    let saved = JSON.parse(readFileSync(join(f.repo, ".live-state/session-results.jsonl"), "utf8"));
    assert.equal(saved.client, "cli-dcr");
    assert.equal(saved.row, undefined);
    assert.equal(saved.clientAttribution, undefined);

    assert.equal(run(f, ["watch", "--all", "--once", "--codex-dcr"]).status, 0);
    saved = JSON.parse(readFileSync(join(f.repo, ".live-state/session-results.jsonl"), "utf8"));
    assert.equal(saved.client, "codex");
    assert.equal(saved.row, "B3");
    assert.equal(saved.clientVersion, "codex 1.2.3");
    assert.equal(saved.clientAttribution, "operator-annotated");
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("Codex DCR attribution rejects the wrong id shape and non-loopback redirects", () => {
  const flow = (clientId, redirectHost) => ({
    clientId,
    events: [{ event: "oauth.authorize.prepare", status: "success", clientId, redirectHost }],
  });
  const generated = `mcpdc_${"b".repeat(32)}`;
  assert.equal(classifyClient(flow("mcpdc_other", "http://localhost:1455/callback"), [], { codexDcr: true }).kind, "cli-dcr");
  assert.equal(classifyClient(flow(generated, "https://client.example/callback"), [], { codexDcr: true }).kind, "dcr-hosted");
  assert.equal(classifyClient(flow(generated, "http://[::1]:1455/callback"), [], { codexDcr: true }).kind, "codex");
});

test("an abandoned registration cannot override the identified flow redirect", () => {
  const clientId = "https://claude.ai/oauth-client";
  const events = audit(clientId);
  events.unshift({
    occurredAt: new Date(Date.parse(events[0].occurredAt) - 1).toISOString(),
    event: "oauth.register", status: "success", redirectHost: "https://claude.ai/callback",
  });
  const flows = buildFlows(events);
  assert.equal(flows.length, 1);
  assert.equal(flows[0].events[0].event, "oauth.register");
  const client = classifyClient(flows[0], flows);
  assert.equal(client.kind, "claude-code");
  assert.equal(client.redirectHost, "localhost");
});

test("watch rejects unknown and repeated options", () => {
  for (const args of [["watch", "--other"], ["watch", "--codex-dcr", "--codex-dcr"]]) {
    const f = fixture();
    try {
      const result = run(f, args);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /usage: session\.mjs watch/);
      assert.equal(existsSync(join(f.repo, ".live-state")), false);
    } finally { rmSync(f.root, { recursive: true, force: true }); }
  }
});

test("watch rejects starting state, empty legs, and session records with unknown fields", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const path = join(f.repo, ".live-state/session.json");
    const state = JSON.parse(readFileSync(path, "utf8"));
    for (const invalid of [{ ...state, status: "starting" }, { ...state, legs: [] }, { ...state, extra: true }]) {
      writeFileSync(path, `${JSON.stringify(invalid)}\n`);
      assert.equal(run(f, ["watch", "--once"]).status, 1);
    }
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("continuous watch stops before attributing a replacement session", async () => {
  const f = fixture();
  let child;
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const leg = join(f.repo, ".live-state/google");
    mkdirSync(leg, { recursive: true });
    writeFileSync(join(leg, "audit.jsonl"), `${audit("https://claude.ai/oauth-client").map(JSON.stringify).join("\n")}\n`);
    child = spawn(process.execPath, [join(f.repo, "session.mjs"), "watch"], {
      cwd: f.repo, env: f.env, stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    await new Promise((resolve) => { setTimeout(resolve, 1_200); });
    assert.equal(run(f, ["serve", "entra"]).status, 0);
    const status = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("watch did not stop after session replacement")), 5_000);
      child.once("error", reject);
      child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
    });
    assert.equal(status, 1);
    assert.match(stderr, /live session changed while watch was running/);
    assert.equal(existsSync(join(f.repo, ".live-state/session-results.jsonl")), false);
  } finally {
    if (child?.exitCode === null) {
      child.kill("SIGKILL");
      await new Promise((resolve) => { child.once("exit", resolve); });
    }
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("watch rechecks its session after opening the result file and before changing it", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const leg = join(f.repo, ".live-state/google");
    const statePath = join(f.repo, ".live-state/session.json");
    const resultsPath = join(f.repo, ".live-state/session-results.jsonl");
    const preload = join(f.root, "replace-session.cjs");
    mkdirSync(leg, { recursive: true });
    writeFileSync(join(leg, "audit.jsonl"), `${audit("https://claude.ai/oauth-client").map(JSON.stringify).join("\n")}\n`);
    writeFileSync(resultsPath, "sentinel\n", { mode: 0o600 });
    writeFileSync(preload, `
const fs = require("node:fs");
const { syncBuiltinESMExports } = require("node:module");
const originalOpenSync = fs.openSync;
let replaced = false;
fs.openSync = function (path, ...args) {
  if (!replaced && String(path).endsWith("/.live-state/session-results.jsonl")) {
    replaced = true;
    const session = JSON.parse(fs.readFileSync(${JSON.stringify(statePath)}, "utf8"));
    session.startedAt = new Date(Date.parse(session.startedAt) + 1).toISOString();
    fs.writeFileSync(${JSON.stringify(statePath)}, \`\${JSON.stringify(session)}\\n\`);
  }
  return originalOpenSync.call(this, path, ...args);
};
syncBuiltinESMExports();
`);
    const result = run(f, ["watch", "--all", "--once"], { NODE_OPTIONS: `--require=${preload}` });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /live session changed while watch was running/);
    assert.equal(readFileSync(resultsPath, "utf8"), "sentinel\n");
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("watch rejects state that is hard-linked, permission-widened, wrongly owned, or under a replaced directory", () => {
  for (const variant of ["hard-link", "mode", "owner", "directory"]) {
    const f = fixture();
    try {
      assert.equal(run(f, ["serve", "google"]).status, 0);
      const stateDir = join(f.repo, ".live-state");
      const statePath = join(stateDir, "session.json");
      if (variant === "hard-link") linkSync(statePath, join(f.root, "other-state"));
      if (variant === "mode") chmodSync(statePath, 0o644);
      if (variant === "directory") chmodSync(stateDir, 0o755);
      if (variant === "owner") assert.throws(() => readPrivateJson(statePath, statSync(statePath).uid + 1), /not private/);
      else assert.equal(run(f, ["watch", "--once"]).status, 1, variant);
    } finally { rmSync(f.root, { recursive: true, force: true }); }
  }

  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const stateDir = join(f.repo, ".live-state");
    const moved = join(f.repo, ".live-state-private");
    renameSync(stateDir, moved);
    symlinkSync(moved, stateDir);
    assert.equal(run(f, ["watch", "--once"]).status, 1);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("default watch reports a flow that was incomplete when watching began", async () => {
  const f = fixture();
  let child;
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const leg = join(f.repo, ".live-state/google");
    mkdirSync(leg, { recursive: true });
    const events = audit("https://claude.ai/oauth-client");
    const auditPath = join(leg, "audit.jsonl");
    writeFileSync(auditPath, `${events.slice(0, 3).map(JSON.stringify).join("\n")}\n`);
    child = spawn(process.execPath, [join(f.repo, "session.mjs"), "watch"], {
      cwd: f.repo, env: f.env, stdio: ["ignore", "pipe", "pipe"],
    });
    await new Promise((resolve) => { setTimeout(resolve, 1_200); });
    appendFileSync(auditPath, `${events.slice(3).map(JSON.stringify).join("\n")}\n`);
    const output = await waitForOutput(child, /PASS A3 google Claude Code/);
    assert.match(output, /PASS A3 google Claude Code/);
    child.kill("SIGINT");
    const code = await new Promise((resolve) => { child.once("exit", resolve); });
    assert.equal(code, 0);
    const saved = JSON.parse(readFileSync(join(f.repo, ".live-state/session-results.jsonl"), "utf8"));
    assert.equal(saved.verdict, "PASS");
  } finally {
    if (child?.exitCode === null) child.kill("SIGKILL");
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("reused-client attempts split and later protected requests stay ambiguous", () => {
  const clientId = "stored-client";
  const events = audit(clientId, true);
  const second = audit(clientId, true, Date.parse(events.at(-1).occurredAt) + 1);
  second.shift();
  const flows = buildFlows([...events, ...second]);
  assert.equal(flows.length, 2);
  assert.deepEqual(flows.map((flow) => flow.events.filter((event) => event.event === "oauth.authorize.prepare").length), [1, 1]);
  assert.deepEqual(flows.map((flow) => flow.events.filter((event) => event.event === "oauth.token.authorization_code").length), [1, 1]);
  assert.equal(flows[0].events[0].event, "oauth.cimd.fetch");
  assert.equal(flows[1].events[0].event, "identity.verify");
  assert.deepEqual(flows.map(outcomeOf), [
    { verdict: "PASS", toolCalls: 1, ambiguousToolCalls: 1 },
    { verdict: "TOKEN_ONLY", toolCalls: 0, ambiguousToolCalls: 1 },
  ]);
});

test("a protected request before the code exchange does not turn the later token into PASS", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const leg = join(f.repo, ".live-state/google");
    mkdirSync(leg, { recursive: true });
    const events = audit("https://claude.ai/oauth-client", false);
    events.splice(-1, 0, { ...events.at(-1), event: "auth.request" });
    writeFileSync(join(leg, "audit.jsonl"), `${events.map(JSON.stringify).join("\n")}\n`);
    assert.equal(run(f, ["watch", "--all", "--once"]).status, 0);
    const saved = JSON.parse(readFileSync(join(f.repo, ".live-state/session-results.jsonl"), "utf8"));
    assert.equal(saved.verdict, "TOKEN_ONLY");
    assert.equal(saved.toolCalls, 0);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("watch fails closed on malformed audit JSON and writes no result", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "entra"]).status, 0);
    const leg = join(f.repo, ".live-state/entra");
    mkdirSync(leg, { recursive: true });
    writeFileSync(join(leg, "audit.jsonl"), "{not-json}\n");
    const result = run(f, ["watch", "--all", "--once"]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /audit trail is unreadable/);
    assert.equal(existsSync(join(f.repo, ".live-state/session-results.jsonl")), false);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("watch refuses a symlinked audit trail and writes no result", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "entra"]).status, 0);
    const leg = join(f.repo, ".live-state/entra");
    const target = join(f.root, "audit.jsonl");
    mkdirSync(leg, { recursive: true });
    writeFileSync(target, `${audit("https://claude.ai/oauth-client").map(JSON.stringify).join("\n")}\n`);
    symlinkSync(target, join(leg, "audit.jsonl"));
    assert.equal(run(f, ["watch", "--all", "--once"]).status, 1);
    assert.equal(existsSync(join(f.repo, ".live-state/session-results.jsonl")), false);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("one-shot watch ignores audit events from before the current serve session", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const leg = join(f.repo, ".live-state/google");
    mkdirSync(leg, { recursive: true });
    writeFileSync(join(leg, "audit.jsonl"), `${audit("https://claude.ai/oauth-client", true, Date.parse("2020-01-01T00:00:00.000Z")).map(JSON.stringify).join("\n")}\n`);
    const result = run(f, ["watch", "--all", "--once"]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /saved 0 result/);
    assert.equal(readFileSync(join(f.repo, ".live-state/session-results.jsonl"), "utf8"), "");
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("an unattributed identity denial does not rewrite the preceding completed flow", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const leg = join(f.repo, ".live-state/google");
    mkdirSync(leg, { recursive: true });
    const events = audit("https://claude.ai/oauth-client");
    events.push({
      occurredAt: new Date(Date.parse(events.at(-1).occurredAt) + 1).toISOString(),
      event: "identity.verify", status: "failure", reason: "identity_rejected",
    });
    writeFileSync(join(leg, "audit.jsonl"), `${events.map(JSON.stringify).join("\n")}\n`);
    const result = run(f, ["watch", "--all", "--once"]);
    assert.equal(result.status, 0, result.stderr);
    const saved = lines(join(f.repo, ".live-state/session-results.jsonl")).map(JSON.parse);
    assert.equal(saved.length, 2);
    assert.equal(saved[0].verdict, "PASS");
    assert.equal(saved[0].row, "A3");
    assert.equal(saved[1].verdict, "DENIED");
    assert.equal(saved[1].client, "unattributed");
    assert.equal(saved[1].row, undefined);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("a hard-linked result path is rejected before its other name is truncated", () => {
  const root = mkdtempSync(join(tmpdir(), "mcp-sso-session-results-"));
  try {
    const original = join(root, "original");
    const results = join(root, "results.jsonl");
    writeFileSync(original, "keep\n", { mode: 0o600 });
    linkSync(original, results);
    assert.throws(() => writeResults(results, [{ verdict: "PASS" }], { replace: true }), /single-link|private regular file/);
    assert.equal(readFileSync(original, "utf8"), "keep\n");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("audit reads reject non-files, oversized input, unknown events, and wrong field types", () => {
  const root = mkdtempSync(join(tmpdir(), "mcp-sso-session-audit-"));
  const path = join(root, "audit.jsonl");
  try {
    assert.throws(() => readAudit(root), /bounded regular file/);
    writeFileSync(path, "x".repeat(10 * 1024 * 1024 + 1));
    assert.throws(() => readAudit(path), /size limit|bounded regular file/);
    for (const row of [
      { occurredAt: new Date().toISOString(), event: "unknown", status: "success" },
      { occurredAt: new Date().toISOString(), event: "auth.request", status: 200 },
    ]) {
      writeFileSync(path, `${JSON.stringify(row)}\n`);
      assert.throws(() => readAudit(path), /invalid status|valid event status/);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("known non-session audit events are accepted and ignored by session flows", () => {
  const root = mkdtempSync(join(tmpdir(), "mcp-sso-session-audit-known-"));
  const path = join(root, "audit.jsonl");
  try {
    const sessionEvents = audit("https://claude.ai/oauth-client");
    const unrelatedNames = [
      "oauth.pairing.attempt", "oauth.device.authorization", "oauth.device.approve",
      "oauth.token.device_code", "oauth.token.client_credentials", "oauth.client.provision",
      "oauth.client.rotate_secret", "oauth.client.disable",
    ];
    const unrelated = unrelatedNames.map((event, index) => ({
      occurredAt: new Date(Date.parse(sessionEvents[1].occurredAt) + index + 1).toISOString(),
      event, status: "success", clientId: "unrelated-client",
    }));
    writeFileSync(path, `${[...sessionEvents.slice(0, 2), ...unrelated, ...sessionEvents.slice(2)]
      .map(JSON.stringify).join("\n")}\n`);
    const rows = readAudit(path);
    assert.equal(rows.length, sessionEvents.length + unrelated.length);
    const flows = buildFlows(rows);
    assert.equal(flows.length, 1);
    assert.deepEqual(flows[0].events.map((event) => event.event), sessionEvents.map((event) => event.event));
    assert.deepEqual(outcomeOf(flows[0]), { verdict: "PASS", toolCalls: 1, ambiguousToolCalls: 0 });
  } finally { rmSync(root, { recursive: true, force: true }); }
});
