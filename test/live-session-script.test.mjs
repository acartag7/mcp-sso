import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  appendFileSync, chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { buildFlows, flowKey, outcomeOf, readAudit } from "../scripts/live/session-support.mjs";

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
[[ "\${MCP_SSO_SESSION_READY_FD-}" == "3" ]] || exit 91
[[ "\${MCP_SSO_SESSION_PARENT_FD-}" == "4" ]] || exit 92
if [[ "\${FAKE_SERVE_STATUS:-0}" != "0" ]]; then exit "$FAKE_SERVE_STATUS"; fi
case "\${FAKE_READY_MARKER-}" in
  bad) printf 'not-ready\n' >&3 ;;
  none) : ;;
  *) printf 'ready\n' >&3 ;;
esac
exec 3>&-
if [[ "\${FAKE_SERVE_WAIT-}" == "true" ]]; then
  (
    while IFS= read -r -u 4; do :; done
    printf parent-gone > "$PARENT_GONE_FILE"
    kill -TERM "$$" 2>/dev/null || true
  ) &
  trap 'printf terminated > "$SERVE_TERMINATED_FILE"; exit 143' TERM
  printf '%s' "$$" > "$SERVE_PID_FILE"
  printf started > "$STARTED_FILE"
  while true; do sleep 0.1; done
fi
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
  return { root, repo, env, serveLog: env.SERVE_LOG, clientLog: env.CLIENT_LOG };
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

function waitForSession(path) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 5_000;
    const poll = () => {
      if (existsSync(path)) { resolve(); return; }
      if (Date.now() >= deadline) reject(new Error(`timed out waiting for ${path}`));
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
    child.once("error", reject);
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

test("serve records a ready session and cleans its fixed client entries", () => {
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
    assert.equal(state.clean, true);
    assert.equal(statSync(join(f.repo, ".live-state")).mode & 0o077, 0);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("serve failures leave no session and still attempt cleanup", () => {
  for (const extraEnv of [{ FAKE_SERVE_STATUS: "23" }, { FAKE_READY_MARKER: "bad" }, { FAKE_READY_MARKER: "none" }]) {
    const f = fixture();
    try {
      const result = run(f, ["serve", "entra"], extraEnv);
      assert.notEqual(result.status, 0, result.stderr);
      assert.equal(existsSync(join(f.repo, ".live-state/session.json")), false);
      assert.deepEqual(lines(f.clientLog), [
        "claude mcp remove mcp-sso-live-entra", "codex mcp remove mcp-sso-live-entra",
      ]);
    } finally { rmSync(f.root, { recursive: true, force: true }); }
  }
});

test("killing the wrapper closes the liveness pipe and stops serve.sh", async () => {
  const f = fixture();
  let servePid;
  try {
    const child = spawn(process.execPath, [join(f.repo, "session.mjs"), "serve", "google"], {
      cwd: f.repo, env: { ...f.env, FAKE_SERVE_WAIT: "true" }, stdio: "ignore",
    });
    await waitForSession(join(f.repo, ".live-state/session.json"));
    await waitForFile(f.env.SERVE_PID_FILE);
    servePid = Number(readFileSync(f.env.SERVE_PID_FILE, "utf8"));
    child.kill("SIGKILL");
    await new Promise((resolve) => { child.once("exit", resolve); });
    await waitForFile(f.env.PARENT_GONE_FILE);
    await waitForFile(f.env.SERVE_TERMINATED_FILE);
    assert.equal(run(f, ["cleanup"]).status, 0);
    assert.equal(lines(f.clientLog).length, 6);
  } finally {
    if (servePid) try { process.kill(-servePid, "SIGKILL"); } catch { /* already gone */ }
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("arguments are checked before serving or cleanup", () => {
  for (const { args, env } of [
    { args: ["serve", "other"] }, { args: ["serve", "google", "google"] },
    { args: ["serve", "google"], env: { MCP_SSO_DCR_MODE: "other" } }, { args: ["watch", "--other"] },
  ]) {
    const f = fixture();
    try {
      const result = run(f, args, env);
      assert.equal(result.status, 1);
      assert.equal(existsSync(f.serveLog), false);
      assert.equal(existsSync(f.clientLog), false);
      assert.equal(existsSync(join(f.repo, ".live-state")), false);
    } finally { rmSync(f.root, { recursive: true, force: true }); }
  }
});

test("cleanup attempts all six reserved entries and continues after a failure", () => {
  const f = fixture();
  try {
    const result = run(f, ["cleanup"], { FAIL_TARGET: "claude:mcp-sso-live-entra", ABSENT_TARGET: "claude:mcp-sso-live-google" });
    assert.equal(result.status, 1);
    assert.deepEqual(lines(f.clientLog), [
      "claude mcp remove mcp-sso-live-cloudflare_access", "codex mcp remove mcp-sso-live-cloudflare_access",
      "claude mcp remove mcp-sso-live-entra", "codex mcp remove mcp-sso-live-entra",
      "claude mcp remove mcp-sso-live-google", "codex mcp remove mcp-sso-live-google",
    ]);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("a same-client cached-token request cannot upgrade a token observation", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const leg = join(f.repo, ".live-state/google");
    mkdirSync(leg, { recursive: true });
    writeFileSync(join(leg, "audit.jsonl"), `${audit("https://claude.ai/oauth-client").map(JSON.stringify).join("\n")}\n`);
    const result = run(f, ["watch", "--all", "--once"]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /TOKEN A3 google Claude Code/);
    assert.match(result.stdout, /REQUEST unattributed google unattributed protected request/);
    const saved = lines(join(f.repo, ".live-state/session-results.jsonl")).map((line) => JSON.parse(line));
    assert.deepEqual(saved.map(({ verdict }) => verdict), ["TOKEN", "REQUEST"]);
    assert.deepEqual(saved.map(({ protectedRequests }) => protectedRequests), [0, 1]);
    assert.equal(saved[0].clientVersion, "claude 1.2.3");
    assert.equal(saved[1].client, "unattributed");
    assert.equal(saved[1].row, undefined);
    assert.equal(saved[1].clientVersion, undefined);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("watch records TOKEN and explicit Codex dynamic registration", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const leg = join(f.repo, ".live-state/google");
    mkdirSync(leg, { recursive: true });
    const clientId = `mcpdc_${"a".repeat(32)}`;
    writeFileSync(join(leg, "audit.jsonl"), `${audit(clientId, false).map(JSON.stringify).join("\n")}\n`);
    assert.equal(run(f, ["watch", "--all", "--once", "--codex-dcr"]).status, 0);
    const saved = JSON.parse(readFileSync(join(f.repo, ".live-state/session-results.jsonl"), "utf8"));
    assert.equal(saved.verdict, "TOKEN");
    assert.equal(saved.client, "codex");
    assert.equal(saved.row, "B3");
    assert.equal(saved.clientAttribution, "operator-annotated");
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("default watch reports a flow that settles after watch starts", async () => {
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
    const output = await waitForOutput(child, /REQUEST unattributed google unattributed protected request/);
    assert.match(output, /TOKEN A3 google Claude Code/);
    assert.match(output, /REQUEST unattributed google unattributed protected request/);
    child.kill("SIGINT");
    assert.equal(await new Promise((resolve) => { child.once("exit", resolve); }), 0);
  } finally {
    if (child?.exitCode === null) child.kill("SIGKILL");
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("a request shared by loopback and hosted attempts stays unattributed", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const clientId = "https://claude.ai/oauth-client";
    const at = (offset) => new Date(Date.now() + 1_000 + offset).toISOString();
    const rows = [
      { occurredAt: at(0), event: "oauth.cimd.fetch", status: "success", clientId },
      { occurredAt: at(1), event: "oauth.authorize.prepare", status: "success", clientId, redirectHost: "http://localhost:49152/callback" },
      { occurredAt: at(2), event: "oauth.token.authorization_code", status: "success", clientId },
      { occurredAt: at(3), event: "oauth.authorize.prepare", status: "success", clientId, redirectHost: "https://claude.ai/callback" },
      { occurredAt: at(4), event: "oauth.token.authorization_code", status: "success", clientId },
      { occurredAt: at(5), event: "auth.request", status: "success", clientId },
    ];
    const leg = join(f.repo, ".live-state/google");
    mkdirSync(leg, { recursive: true });
    writeFileSync(join(leg, "audit.jsonl"), `${rows.map(JSON.stringify).join("\n")}\n`);
    assert.equal(run(f, ["watch", "--all", "--once"]).status, 0);
    const saved = lines(join(f.repo, ".live-state/session-results.jsonl")).map((line) => JSON.parse(line));
    assert.deepEqual(saved.map(({ row }) => row), ["A3", "F3", undefined]);
    assert.equal(saved[2].verdict, "REQUEST");
    assert.equal(saved[2].client, "unattributed");
    assert.equal(saved[2].redirectHost, "");
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("flow grouping keeps requests, repeated attempts, and unattributed denials separate", () => {
  const clientId = "stored-client";
  const events = audit(clientId, true, Date.parse("2026-08-28T20:00:00.000Z"));
  const second = audit(clientId, true, Date.parse(events.at(-1).occurredAt) + 1);
  second.shift();
  const denial = {
    occurredAt: new Date(Date.parse(second.at(-1).occurredAt) + 1).toISOString(),
    event: "identity.verify", status: "failure", reason: "identity_rejected",
  };
  const flows = buildFlows([...events, ...second, denial]);
  assert.equal(flows.length, 5);
  assert.equal(new Set(flows.map((flow) => flowKey("google", flow))).size, 5);
  assert.deepEqual(flows.map((flow) => outcomeOf(flow).verdict), [
    "TOKEN", "REQUEST", "TOKEN", "REQUEST", "DENIED",
  ]);
});

test("audit parsing rejects malformed rows and ignores known unrelated events", () => {
  const root = mkdtempSync(join(tmpdir(), "mcp-sso-session-audit-"));
  const path = join(root, "audit.jsonl");
  try {
    const rows = audit("https://claude.ai/oauth-client");
    rows.splice(2, 0, {
      occurredAt: new Date(Date.parse(rows[1].occurredAt) + 1).toISOString(),
      event: "oauth.token.client_credentials", status: "failure", clientId: "other",
    });
    writeFileSync(path, `${rows.map(JSON.stringify).join("\n")}\n`);
    assert.equal(buildFlows(readAudit(path)).length, 2);
    for (const body of [
      "{not-json}\n", `${JSON.stringify(rows[0])}\n\n${JSON.stringify(rows[1])}\n`,
      `${JSON.stringify({ ...rows[0], event: 42 })}\n`, "x".repeat(10 * 1024 * 1024 + 1),
    ]) {
      writeFileSync(path, body);
      assert.throws(() => readAudit(path));
    }
    rmSync(path);
    mkdirSync(path);
    assert.throws(() => readAudit(path));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("watch rejects malformed session state without writing results", () => {
  for (const body of [
    "", "{not-json}\n", `${JSON.stringify({ version: 1, legs: [] })}\n`,
    `${JSON.stringify({ version: 1, legs: ["google"], mode: "stored", commit: "a".repeat(40), clean: true, startedAt: "2026-08-28T20:00:00.000Z", extra: true })}\n`,
  ]) {
    const f = fixture();
    try {
      mkdirSync(join(f.repo, ".live-state"), { recursive: true });
      writeFileSync(join(f.repo, ".live-state/session.json"), body);
      assert.equal(run(f, ["watch", "--all", "--once"]).status, 1);
      assert.equal(existsSync(join(f.repo, ".live-state/session-results.jsonl")), false);
    } finally { rmSync(f.root, { recursive: true, force: true }); }
  }
});
