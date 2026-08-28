import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync, copyFileSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { classifyClient, readAudit, writeResults } from "../scripts/live/session-support.mjs";

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
if [[ "\${FAKE_SERVE_STATUS:-0}" == "0" && "\${MCP_SSO_SESSION_READY_FD-}" == "3" ]]; then
  case "\${FAKE_READY_MARKER-}" in
    bad) printf 'not-ready\n' >&3 ;;
    none) : ;;
    *) printf 'ready\n' >&3 ;;
  esac
  exec 3>&-
fi
if [[ "\${FAKE_SERVE_WAIT-}" == "true" ]]; then
  trap 'exit 130' INT
  trap 'exit 143' TERM
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
    STARTED_FILE: join(root, "started"),
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

test("session serve rejects a malformed readiness marker and leaves no usable state", () => {
  const f = fixture();
  try {
    const result = run(f, ["serve", "google"], { FAKE_READY_MARKER: "bad" });
    assert.equal(result.status, 1, result.stderr);
    assert.equal(existsSync(join(f.repo, ".live-state/session.json")), false);
    assert.equal(run(f, ["watch", "--once"]).status, 1);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("Ctrl-C reaches serve.sh and then cleans the selected client entries", async () => {
  const f = fixture();
  try {
    const child = spawn(process.execPath, [join(f.repo, "session.mjs"), "serve", "cloudflare_access"], {
      cwd: f.repo, env: { ...f.env, FAKE_SERVE_WAIT: "true" }, stdio: "ignore",
    });
    await waitForFile(f.env.STARTED_FILE);
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

test("watch rejects starting state and session records with unknown fields", () => {
  const f = fixture();
  try {
    assert.equal(run(f, ["serve", "google"]).status, 0);
    const path = join(f.repo, ".live-state/session.json");
    const state = JSON.parse(readFileSync(path, "utf8"));
    for (const invalid of [{ ...state, status: "starting" }, { ...state, extra: true }]) {
      writeFileSync(path, `${JSON.stringify(invalid)}\n`);
      assert.equal(run(f, ["watch", "--once"]).status, 1);
    }
  } finally { rmSync(f.root, { recursive: true, force: true }); }
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
