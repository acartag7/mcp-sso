// Behavioural coverage for scripts/live/run.sh: the shipped script is spawned
// against a fixture infrastructure wrapper and fixture entry points that record
// the environment they receive. Nothing here reads run.sh as text.
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import {
  chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync,
  symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const TENANT = "11111111-2222-3333-4444-555555555555";
const CLIENT = "66666666-7777-8888-9999-aaaaaaaaaaaa";
const MAPPED = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
const UNMAPPED = "01234567-89ab-cdef-0123-456789abcdef";
const ORIGINS = { cloudflare_access: "https://cf.example", entra: "https://entra.example", google: "https://google.example" };

const executable = (path, source) => { writeFileSync(path, source); chmodSync(path, 0o700); };
const CAPTURE_ENTRY = 'import { writeFileSync } from "node:fs";\nimport { join } from "node:path";\nwriteFileSync(join(process.env.TMPDIR, "capture.json"), JSON.stringify({ env: process.env, pid: process.pid }));\n';

/** A fixture repository whose scripts/live holds the REAL run.sh and
 *  run-support.mjs, whose src/ and example app are the real ones (symlinked, so
 *  the preflight exercises the shipped constructors), and whose entry points are
 *  capture stubs. The infrastructure wrapper answers with canned outputs and
 *  logs every call. */
function makeFixture() {
  const fixture = mkdtempSync(join(tmpdir(), "mcp-sso-live-run-"));
  const repo = join(fixture, "repo");
  const infra = join(fixture, "infra");
  const home = join(fixture, "home");
  mkdirSync(join(repo, "scripts/live"), { recursive: true });
  mkdirSync(join(repo, "examples/fastify-sqlite"), { recursive: true });
  mkdirSync(join(infra, "scripts"), { recursive: true });
  mkdirSync(home, { recursive: true });
  symlinkSync(join(ROOT, "src"), join(repo, "src"));
  for (const file of ["app.ts", "registration-rate-limit.ts", "trusted-proxy.ts"]) {
    symlinkSync(join(ROOT, "examples/fastify-sqlite", file), join(repo, "examples/fastify-sqlite", file));
  }
  copyFileSync(join(ROOT, "scripts/live/run.sh"), join(repo, "scripts/live/run.sh"));
  chmodSync(join(repo, "scripts/live/run.sh"), 0o700);
  copyFileSync(join(ROOT, "scripts/live/run-support.mjs"), join(repo, "scripts/live/run-support.mjs"));
  for (const entry of ["probe-cloudflare.mjs", "probe-entra.mjs", "probe-google.mjs", "probe-e2e.mjs"]) {
    writeFileSync(join(repo, "scripts/live", entry), CAPTURE_ENTRY);
  }
  writeFileSync(join(repo, "examples/fastify-sqlite/index.ts"), CAPTURE_ENTRY);
  executable(join(infra, "scripts/tofu-run.sh"), `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$TOFU_LOG"
stack="$1"; name="$4"
case "$stack:$name" in
  cf:issuer_origins) printf '%s' '${JSON.stringify(ORIGINS)}' ;;
  cf:cf_access_issuer) printf '%s' 'https://team.cloudflareaccess.com' ;;
  cf:cf_access_certs_url) printf '%s' 'https://team.cloudflareaccess.com/cdn-cgi/access/certs' ;;
  cf:cf_access_audience) printf '%s' 'fixture-audience-tag' ;;
  entra:entra_tenant_id) printf '%s' '${TENANT}' ;;
  entra:entra_client_id) printf '%s' '${CLIENT}' ;;
  entra:entra_client_secret) printf '%s' "\${FAKE_ENTRA_SECRET-fixture-entra-secret}" ;;
  entra:entra_redirect_uri) printf '%s' 'https://entra.example/oauth/callback' ;;
  entra:unmapped_group_object_id_do_not_map) printf '%s' "\${FAKE_UNMAPPED-${UNMAPPED}}" ;;
  entra:group_authorization_mapping) printf '%s' '{"${MAPPED}":["mcp:read"]}' ;;
  *) exit 1 ;;
esac
`);
  const bin = join(fixture, "bin");
  mkdirSync(bin);
  executable(join(bin, "cloudflared"), `#!/usr/bin/env bash
[[ "$1 $2" == "access token" && -n "\${FAKE_ASSERTION-}" ]] || exit 1
printf '%s' "$FAKE_ASSERTION"
`);
  // The runner names the runtime commit and refuses uncommitted tracked
  // changes, so the fixture repository is a committed git checkout.
  const git = (...args) => execFileSync("git", ["-C", repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", ...args], { stdio: "ignore" });
  git("init", "-q");
  git("add", "-A");
  git("commit", "-q", "-m", "fixture");
  return { fixture, repo, infra, home, bin };
}

function runScript(fx, entry, leg, extraEnv = {}) {
  const runDir = join(fx.fixture, `run-${Math.random().toString(16).slice(2)}`);
  mkdirSync(runDir);
  const capture = join(runDir, "capture.json");
  const tofuLog = join(runDir, "tofu.log");
  return new Promise((resolve, reject) => {
    const child = spawn(join(fx.repo, "scripts/live/run.sh"), [entry, leg], {
      env: {
        PATH: `${fx.bin}:${process.env.PATH}`, HOME: fx.home, TMPDIR: runDir,
        MCP_SSO_INFRA_DIR: fx.infra, MCP_SSO_CLOUDFLARE_STACK: "cf", MCP_SSO_ENTRA_STACK: "entra",
        TOFU_LOG: tofuLog, ...extraEnv,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    let stdout = "";
    child.stderr.setEncoding("utf8");
    child.stdout.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.once("error", reject);
    child.once("exit", (code) => {
      const record = existsSync(capture) ? JSON.parse(readFileSync(capture, "utf8")) : undefined;
      resolve({
        code, stderr, stdout, childPid: child.pid,
        captured: record?.env, entryPid: record?.pid,
        tofuCalls: existsSync(tofuLog) ? readFileSync(tofuLog, "utf8").trim().split("\n") : [],
      });
    });
  });
}

// The entry's environment is an allowlist: exactly the runner's variables plus
// PATH/HOME/TMPDIR/LANG/LC_ALL. macOS injects __CF_USER_TEXT_ENCODING into every
// process; it is the OS, not the shell, and is ignored here.
const BASE_KEYS = ["PATH", "HOME", "TMPDIR"];
const RUNNER_KEYS = ["OAUTH_ISSUER", "OAUTH_RESOURCE", "OAUTH_ALLOWED_ORIGINS", "OAUTH_REDIRECT_ALLOWLIST",
  "OAUTH_CONSENT_SIGNING_SECRET", "OAUTH_SIGNING_PRIVATE_JWK", "OAUTH_SIGNING_KEY_ID", "OAUTH_DCR_MODE",
  "OAUTH_SCOPE_CATALOG", "OAUTH_DEFAULT_SCOPES", "PROBE_CLIENT_REDIRECT", "PROBE_APP_CALLBACK"];
const LEG_KEYS = {
  entra: ["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET", "ENTRA_REDIRECT_URI", "ENTRA_UNMAPPED_GROUP", "ENTRA_GROUP_AUTHORIZATION_JSON"],
  cloudflare_access: ["CF_ACCESS_ISSUER", "CF_ACCESS_CERTS_URL", "CF_ACCESS_AUDIENCE"],
  google: ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI"],
};
const envKeys = (env) => Object.keys(env).filter((key) => !key.startsWith("__CF_") && key !== "LANG" && key !== "LC_ALL").sort();
const expectKeys = (env, extra) => assert.deepEqual(envKeys(env), [...BASE_KEYS, ...RUNNER_KEYS, ...extra].sort());

test("run.sh assembles the selected leg from stack outputs and clears stale selectors", async (t) => {
  const fx = makeFixture();
  try {
    await t.test("entra probe: canned outputs reach the entry; inherited selectors and OAuth overrides do not", async () => {
      const result = await runScript(fx, "scripts/live/probe-entra.mjs", "entra", {
        GOOGLE_CLIENT_ID: "stale", OIDC_ISSUER: "https://stale.example", CF_ACCESS_AUDIENCE: "stale",
        OAUTH_ALLOW_INSECURE_LOCALHOST: "true", OAUTH_REDIRECT_ALLOWLIST_MODE: "replace",
        PROBE_CLIENT_REDIRECT: "https://stale.example/cb", ENTRA_SUBJECT_ALLOWLIST: "stale@example",
        HOST: "127.0.0.1", PORT: "1", MCP_SSO_TRUSTED_PROXIES: "10.0.0.0/8", NODE_TLS_REJECT_UNAUTHORIZED: "0",
        NODE_OPTIONS: "--require=/nonexistent", NODE_EXTRA_CA_CERTS: "/nonexistent", REDIS_URL: "redis://stale:1",
        AWS_PROFILE: "stale", MCP_SSO_DIR: "/stale",
      });
      assert.equal(result.code, 0, result.stderr);
      const env = result.captured;
      expectKeys(env, LEG_KEYS.entra);
      assert.equal(result.entryPid, result.childPid, "run.sh execs the entry in place; the started PID is the entry");
      assert.equal(env.OAUTH_ISSUER, ORIGINS.entra);
      assert.equal(env.ENTRA_TENANT_ID, TENANT);
      assert.equal(env.ENTRA_CLIENT_ID, CLIENT);
      assert.equal(env.ENTRA_CLIENT_SECRET, "fixture-entra-secret");
      assert.equal(env.ENTRA_REDIRECT_URI, "https://entra.example/oauth/callback");
      assert.equal(env.ENTRA_UNMAPPED_GROUP, UNMAPPED);
      assert.deepEqual(JSON.parse(env.ENTRA_GROUP_AUTHORIZATION_JSON), { mapping: { [MAPPED]: ["mcp:read"] } });
      assert.equal(env.PROBE_CLIENT_REDIRECT, "https://claude.ai/api/mcp/auth_callback");
      assert.equal(env.PROBE_APP_CALLBACK, "https://entra.example/app/callback");
      assert.equal(env.OAUTH_REDIRECT_ALLOWLIST, "https://entra.example/app/callback,http://localhost,http://127.0.0.1");
      assert.equal(env.OAUTH_DCR_MODE, "stored");
      assert.equal(env.OAUTH_RESOURCE, "https://entra.example/mcp");
      assert.ok(env.OAUTH_CONSENT_SIGNING_SECRET.length >= 40);
      assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /fixture-entra-secret/, "run.sh never prints a stack secret");
      assert.equal(JSON.parse(env.OAUTH_SIGNING_PRIVATE_JWK).kty, "EC");
    });
    await t.test("entra deny legs: one marked channel per run; bare ENTRA_* names never pass", async () => {
      const WRONG_TENANT = "00000000-0000-0000-0000-000000000000";
      const WRONG_SUBJECT = "nobody@wrong.example";
      // One channel at a time (both set at once is ambiguous evidence — tenant
      // validation would mask the allowlist denial — and is refused below).
      const tenantRun = await runScript(fx, "scripts/live/probe-entra.mjs", "entra", {
        MCP_SSO_ENTRA_ALLOWED_TENANT_IDS: WRONG_TENANT,
        ENTRA_ALLOWED_TENANT_IDS: "stale-tenant", ENTRA_SUBJECT_ALLOWLIST: "stale@example",
      });
      assert.equal(tenantRun.code, 0, tenantRun.stderr);
      expectKeys(tenantRun.captured, [...LEG_KEYS.entra, "ENTRA_ALLOWED_TENANT_IDS"]);
      assert.equal(tenantRun.captured.ENTRA_ALLOWED_TENANT_IDS, WRONG_TENANT, "the marked channel's value, not the ambient bare name");
      const subjectRun = await runScript(fx, "scripts/live/probe-entra.mjs", "entra", {
        MCP_SSO_ENTRA_SUBJECT_ALLOWLIST: WRONG_SUBJECT,
        ENTRA_ALLOWED_TENANT_IDS: "stale-tenant", ENTRA_SUBJECT_ALLOWLIST: "stale@example",
      });
      assert.equal(subjectRun.code, 0, subjectRun.stderr);
      expectKeys(subjectRun.captured, [...LEG_KEYS.entra, "ENTRA_SUBJECT_ALLOWLIST"]);
      assert.equal(subjectRun.captured.ENTRA_SUBJECT_ALLOWLIST, WRONG_SUBJECT, "the marked channel's value, not the ambient bare name");
      const bothSet = await runScript(fx, "scripts/live/probe-entra.mjs", "entra", {
        MCP_SSO_ENTRA_ALLOWED_TENANT_IDS: WRONG_TENANT, MCP_SSO_ENTRA_SUBJECT_ALLOWLIST: WRONG_SUBJECT,
      });
      assert.equal(bothSet.code, 1);
      assert.match(bothSet.stderr, /only ONE Entra deny channel/);
      assert.equal(bothSet.captured, undefined, "the refusal stops before the entry runs");
      // A value that trims to nothing is the positive leg in disguise (the
      // example's listEnv would treat it as unset) and is refused.
      const blank = await runScript(fx, "scripts/live/probe-entra.mjs", "entra", {
        MCP_SSO_ENTRA_SUBJECT_ALLOWLIST: " , ",
      });
      assert.equal(blank.code, 1);
      assert.match(blank.stderr, /no nonempty entry after trimming/);
      const bareOnly = await runScript(fx, "scripts/live/probe-entra.mjs", "entra", {
        ENTRA_ALLOWED_TENANT_IDS: "stale-tenant", ENTRA_SUBJECT_ALLOWLIST: "stale@example",
      });
      assert.equal(bareOnly.code, 0, bareOnly.stderr);
      expectKeys(bareOnly.captured, LEG_KEYS.entra);
    });
    await t.test("cloudflare probe: the Access assertion is minted by cloudflared, never inherited", async () => {
      const denied = await runScript(fx, "scripts/live/probe-cloudflare.mjs", "cloudflare_access", { CF_ACCESS_ASSERTION: "stale" });
      assert.equal(denied.code, 1);
      assert.equal(denied.captured, undefined, "no assertion available must stop before the entry");
      assert.match(denied.stderr, /cloudflared access login/);
      const minted = await runScript(fx, "scripts/live/probe-cloudflare.mjs", "cloudflare_access", { FAKE_ASSERTION: "fixture.jwt.value", CF_ACCESS_ASSERTION: "stale" });
      assert.equal(minted.code, 0, minted.stderr);
      assert.equal(minted.captured.CF_ACCESS_ASSERTION, "fixture.jwt.value", "the minted assertion, never the inherited one");
      assert.equal(minted.captured.CF_ACCESS_ISSUER, "https://team.cloudflareaccess.com");
      assert.equal(minted.captured.CF_ACCESS_AUDIENCE, "fixture-audience-tag");
      expectKeys(minted.captured, [...LEG_KEYS.cloudflare_access, "CF_ACCESS_ASSERTION"]);
      assert.ok(minted.tofuCalls.every((call) => call.startsWith("cf ")), "the Entra stack is never read for the Cloudflare leg");
      const served = await runScript(fx, "examples/fastify-sqlite/index.ts", "cloudflare_access", { PORT: "43999" });
      assert.equal(served.code, 0, served.stderr);
      expectKeys(served.captured, [...LEG_KEYS.cloudflare_access, "MCP_SSO_DIR", "OAUTH_SQLITE_FILE", "HOST", "PORT"]);
      assert.equal(served.captured.PORT, "43999", "the server entry keeps the port serve.sh assigned");
      assert.equal(served.captured.HOST, "127.0.0.1", "a tunnel-backed server binds loopback only");
    });
    await t.test("inherited shell tracing is switched off before any secret is handled", async () => {
      const traced = await runScript(fx, "scripts/live/probe-entra.mjs", "entra", { SHELLOPTS: "xtrace", PS4: "+trace+ " });
      assert.equal(traced.code, 0, traced.stderr);
      assert.equal(traced.captured.ENTRA_CLIENT_SECRET, "fixture-entra-secret");
      // Only the two `set` lines that run before tracing is switched off may echo.
      assert.doesNotMatch(traced.stderr, /fixture-entra-secret|\+trace\+ (?!set )/, "xtrace inherited through SHELLOPTS must not echo assignments");
    });
    await t.test("uncommitted tracked changes are refused unless the run is declared non-evidence", async () => {
      const tracked = join(fx.repo, "scripts/live/probe-entra.mjs");
      const original = readFileSync(tracked, "utf8");
      writeFileSync(tracked, `${original}// local edit\n`);
      try {
        const dirty = await runScript(fx, "scripts/live/probe-entra.mjs", "entra");
        assert.equal(dirty.code, 1);
        assert.equal(dirty.captured, undefined, "a dirty tree produces no run");
        assert.deepEqual(dirty.tofuCalls, [], "refused before any stack read");
        assert.match(dirty.stderr, /uncommitted tracked changes/);
        const declared = await runScript(fx, "scripts/live/probe-entra.mjs", "entra", { MCP_SSO_ALLOW_DIRTY: "true" });
        assert.equal(declared.code, 0, declared.stderr);
        assert.match(declared.stderr, /UNCOMMITTED tracked changes — this run is not release evidence/);
      } finally {
        writeFileSync(tracked, original);
      }
      const clean = await runScript(fx, "scripts/live/probe-entra.mjs", "entra");
      assert.equal(clean.code, 0, clean.stderr);
      assert.match(clean.stderr, /^run\.sh: runtime commit [0-9a-f]{40}$/m, "a clean run names its runtime commit");
    });
    await t.test("e2e probe: REDIS_URL passes through and no provider credential is read or handed over", async () => {
      const result = await runScript(fx, "scripts/live/probe-e2e.mjs", "entra", { REDIS_URL: "redis://127.0.0.1:6379", ENTRA_CLIENT_SECRET: "stale" });
      assert.equal(result.code, 0, result.stderr);
      expectKeys(result.captured, ["REDIS_URL"]);
      assert.equal(result.captured.REDIS_URL, "redis://127.0.0.1:6379");
      assert.deepEqual(result.tofuCalls, ["cf output -json issuer_origins"], "only the issuer origin is read for the e2e probe");
    });
    await t.test("unsupported entry/leg pairs and a missing REDIS_URL stop before any stack read", async () => {
      for (const [entry, leg, env] of [
        ["scripts/live/probe-entra.mjs", "google", {}],
        ["scripts/live/probe-google.mjs", "entra", {}],
        ["scripts/live/run-support.mjs", "entra", {}],
        ["scripts/live/probe-e2e.mjs", "entra", {}],
      ]) {
        const result = await runScript(fx, entry, leg, env);
        assert.equal(result.code, 1, `${entry} ${leg}`);
        assert.equal(result.captured, undefined);
        assert.deepEqual(result.tofuCalls, [], `${entry} ${leg} must not read the stacks`);
      }
    });
  } finally {
    rmSync(fx.fixture, { recursive: true, force: true });
  }
});

test("run.sh validates before it touches prior state, and never deletes through a link", async (t) => {
  const fx = makeFixture();
  const stateRoot = join(fx.repo, ".live-state");
  const server = "examples/fastify-sqlite/index.ts";
  try {
    await t.test("a malformed stack output stops the run with the previous leg state intact", async () => {
      mkdirSync(join(stateRoot, "entra"), { recursive: true, mode: 0o700 });
      chmodSync(stateRoot, 0o700);
      writeFileSync(join(stateRoot, "entra/marker"), "previous evidence");
      const bad = await runScript(fx, server, "entra", { FAKE_UNMAPPED: "not-a-guid" });
      assert.equal(bad.code, 1);
      assert.equal(bad.captured, undefined);
      assert.equal(readFileSync(join(stateRoot, "entra/marker"), "utf8"), "previous evidence");
      const mapped = await runScript(fx, server, "entra", { FAKE_UNMAPPED: MAPPED.toUpperCase() });
      assert.equal(mapped.code, 1, "an unmapped fixture that is in the mapping (any case) fails the preflight");
      assert.equal(readFileSync(join(stateRoot, "entra/marker"), "utf8"), "previous evidence");
      const empty = await runScript(fx, server, "entra", { FAKE_ENTRA_SECRET: "" });
      assert.equal(empty.code, 1, "an empty client secret output stops the run");
      assert.equal(readFileSync(join(stateRoot, "entra/marker"), "utf8"), "previous evidence");
      // The runner's own knobs are the sibling of a bad stack output: anything
      // the example would refuse at boot is refused here, before the state moves.
      const stateless = await runScript(fx, server, "entra", { MCP_SSO_DCR_MODE: "stateless" });
      assert.equal(stateless.code, 1, "stateless DCR with the loopback allowlist is refused by the deployment guard before any state moves");
      assert.equal(readFileSync(join(stateRoot, "entra/marker"), "utf8"), "previous evidence");
      const statelessNoLoopback = await runScript(fx, "scripts/live/probe-entra.mjs", "entra", { MCP_SSO_DCR_MODE: "stateless", MCP_SSO_ALLOW_LOOPBACK: "false" });
      assert.equal(statelessNoLoopback.code, 0, statelessNoLoopback.stderr);
      assert.equal(statelessNoLoopback.captured.OAUTH_DCR_MODE, "stateless");
      assert.equal(statelessNoLoopback.captured.OAUTH_REDIRECT_ALLOWLIST, "https://entra.example/app/callback");
    });
    await t.test("the server entry retains the last evidence-bearing leg state; probes never touch it", async () => {
      writeFileSync(join(stateRoot, "entra/audit.jsonl"), "{}\n");
      const probe = await runScript(fx, "scripts/live/probe-entra.mjs", "entra");
      assert.equal(probe.code, 0, probe.stderr);
      assert.equal(readFileSync(join(stateRoot, "entra/marker"), "utf8"), "previous evidence", "a probe run leaves the served leg's state alone");
      const served = await runScript(fx, server, "entra");
      assert.equal(served.code, 0, served.stderr);
      assert.equal(existsSync(join(stateRoot, "entra")), false, "the leaf is left for the library to create");
      assert.equal(readFileSync(join(stateRoot, "entra.previous/marker"), "utf8"), "previous evidence", "the last run's evidence survives one more start");
      assert.equal(served.captured.MCP_SSO_DIR, join(stateRoot, "entra"));
      assert.equal(served.captured.OAUTH_SQLITE_FILE, join(stateRoot, "entra/auth.db"));
      // A start that failed after the preflight leaves a leaf without audit
      // evidence; the retry must not trade the good generation for it.
      mkdirSync(join(stateRoot, "entra"));
      writeFileSync(join(stateRoot, "entra/auth.db"), "failed start");
      const retry = await runScript(fx, server, "entra");
      assert.equal(retry.code, 0, retry.stderr);
      assert.equal(readFileSync(join(stateRoot, "entra.previous/marker"), "utf8"), "previous evidence", "a failed-start retry keeps the last successful evidence");
      mkdirSync(join(stateRoot, "entra"));
      writeFileSync(join(stateRoot, "entra/marker"), "second run");
      writeFileSync(join(stateRoot, "entra/audit.jsonl"), "{}\n");
      const again = await runScript(fx, server, "entra");
      assert.equal(again.code, 0, again.stderr);
      assert.equal(readFileSync(join(stateRoot, "entra.previous/marker"), "utf8"), "second run", "a generation with evidence replaces the one before it");
    });
    await t.test("a previous generation that cannot be removed stops the run before the entry", async () => {
      const locked = join(stateRoot, "entra.previous/locked");
      mkdirSync(locked, { recursive: true });
      writeFileSync(join(locked, "file"), "x");
      chmodSync(locked, 0o500);
      mkdirSync(join(stateRoot, "entra"), { recursive: true });
      writeFileSync(join(stateRoot, "entra/audit.jsonl"), "{}\n"); // evidence: the retained generation is due for replacement
      try {
        const result = await runScript(fx, server, "entra");
        assert.equal(result.code, 1);
        assert.equal(result.captured, undefined);
        assert.equal(existsSync(join(locked, "file")), true);
      } finally {
        chmodSync(locked, 0o700);
      }
    });
    await t.test("a symlinked live-state parent is refused and its target is untouched", async () => {
      rmSync(stateRoot, { recursive: true, force: true });
      const elsewhere = join(fx.fixture, "elsewhere");
      mkdirSync(join(elsewhere, "entra"), { recursive: true });
      chmodSync(elsewhere, 0o700); // owner-only, so the link itself is the only defect
      writeFileSync(join(elsewhere, "entra/marker"), "outside the repository");
      symlinkSync(elsewhere, stateRoot);
      const result = await runScript(fx, server, "entra");
      assert.equal(result.code, 1);
      assert.equal(result.captured, undefined);
      assert.equal(readFileSync(join(elsewhere, "entra/marker"), "utf8"), "outside the repository");
      rmSync(stateRoot, { force: true });
    });
  } finally {
    rmSync(fx.fixture, { recursive: true, force: true });
  }
});

test("run.sh reads the Google credential file as owner-only data, never by sourcing it", async (t) => {
  const fx = makeFixture();
  const file = join(fx.home, ".mcp-sso-google.env");
  try {
    await t.test("a private KEY=VALUE file with the OIDC secret alias supplies both Google values", async () => {
      writeFileSync(file, "# comment\nGOOGLE_CLIENT_ID=fixture-google-id\nOIDC_CLIENT_SECRET=fixture-google-secret\n", { mode: 0o600 });
      chmodSync(file, 0o600);
      const result = await runScript(fx, "scripts/live/probe-google.mjs", "google");
      assert.equal(result.code, 0, result.stderr);
      assert.equal(result.captured.GOOGLE_CLIENT_ID, "fixture-google-id");
      assert.equal(result.captured.GOOGLE_CLIENT_SECRET, "fixture-google-secret");
      assert.equal(result.captured.OIDC_CLIENT_SECRET, undefined, "the alias never reaches the entry under the generic-OIDC name");
      assert.equal(result.captured.GOOGLE_REDIRECT_URI, "https://google.example/oauth/callback");
      assert.ok(result.tofuCalls.every((call) => call.startsWith("cf ")));
      assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /fixture-google-secret|fixture-google-id/, "run.sh never prints the credential");
    });
    await t.test("group/other-readable, symlinked, sourced-shape, and shell-injecting files are refused", async () => {
      chmodSync(file, 0o644);
      const readable = await runScript(fx, "scripts/live/probe-google.mjs", "google");
      assert.equal(readable.code, 1);
      assert.equal(readable.captured, undefined);
      chmodSync(file, 0o600);
      const target = join(fx.fixture, "real-credentials.env");
      writeFileSync(target, "GOOGLE_CLIENT_ID=a\nGOOGLE_CLIENT_SECRET=b\n", { mode: 0o600 });
      rmSync(file);
      symlinkSync(target, file);
      const linked = await runScript(fx, "scripts/live/probe-google.mjs", "google");
      assert.equal(linked.code, 1, "a symlink at the credential path is refused");
      rmSync(file);
      const injected = join(fx.fixture, "injected");
      writeFileSync(file, `GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=$(id>${injected})\n`, { mode: 0o600 });
      const shell = await runScript(fx, "scripts/live/probe-google.mjs", "google");
      assert.equal(shell.code, 0, shell.stderr);
      assert.equal(shell.captured.GOOGLE_CLIENT_SECRET, `$(id>${injected})`, "the value is data");
      assert.equal(existsSync(injected), false, "the credential file is never executed");
      writeFileSync(file, "export GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=s\n", { mode: 0o600 });
      const exported = await runScript(fx, "scripts/live/probe-google.mjs", "google");
      assert.equal(exported.code, 1, "an unsupported key shape is refused rather than sourced");
    });
  } finally {
    rmSync(fx.fixture, { recursive: true, force: true });
  }
});
