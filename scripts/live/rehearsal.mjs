// The release rehearsal: every live row, in order, through run.sh, with one
// receipt at the end. It runs the same way on a laptop (MCP_SSO_INFRA_DIR at the
// private infrastructure checkout) and in CI (MCP_SSO_INFRA_DIR at
// scripts/live/ci/infra with a fetched bundle); this file does not know which.
//
//   node scripts/live/rehearsal.mjs [--out <receipt.json>] [--rows id,id,...]
//
// Exit 0 only when every row is PASS on a clean tree. A BLOCKED row names what
// an operator must arm; it is never evidence and never a pass.
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { privateValues, readPrivateJson } from "./ci/bundle-support.mjs";
import { issuerOriginForLeg, readGoogleCredentialFile } from "./run-support.mjs";
import {
  ROWS, buildReceipt, classifyCommandRun, classifyDriverRun, classifyRun, classifyServeFailure, formatSummary, generations,
} from "./rehearsal-support.mjs";

const REPO = fileURLToPath(new URL("../..", import.meta.url));
const ROW_TIMEOUT_MS = 10 * 60_000;
const SERVE_READY_MS = 120_000;
const MAX_CAPTURE = 1024 * 1024;
const LEAK_NOTE = "output withheld: a private value from the run configuration appeared in it";
/** What a row that `needs` a provided result receives it through. */
const HANDOFF_ENV = Object.freeze({ "cloudflare-assertion": "MCP_SSO_CF_ACCESS_ASSERTION_FILE" });

function parseArgs(argv) {
  const options = { out: join(REPO, ".live-state", "receipt.json"), rows: undefined };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--out" && argv[i + 1]) options.out = resolve(argv[++i]);
    else if (argv[i] === "--rows" && argv[i + 1]) options.rows = new Set(argv[++i].split(",").map((s) => s.trim()).filter(Boolean));
    else throw new Error("usage: rehearsal.mjs [--out <receipt.json>] [--rows id,id]");
  }
  return options;
}

/** Every private value the run configuration holds, so a row that echoes one
 *  is failed and its output withheld. From the CI bundle when present, and from
 *  the Google credential file when one is named; a laptop run without either
 *  scans nothing and relies on the probes' own output guards. */
function collectPrivateValues(env) {
  const values = new Set();
  const dir = env.MCP_SSO_BUNDLE_DIR;
  if (typeof dir === "string" && dir.length > 0 && existsSync(dir)) {
    for (const name of readdirSync(dir)) if (name.endsWith(".json")) privateValues(readPrivateJson(join(dir, name)), values);
  }
  const googleEnv = env.MCP_SSO_GOOGLE_ENV;
  if (typeof googleEnv === "string" && googleEnv.length > 0 && existsSync(googleEnv)) {
    privateValues(readGoogleCredentialFile(googleEnv), values);
  }
  return values;
}

/** The tunnel serve.sh should run: the operator's, or the one the CI bundle names. */
function tunnelId(env) {
  if (typeof env.MCP_SSO_TUNNEL === "string" && env.MCP_SSO_TUNNEL.length > 0) return env.MCP_SSO_TUNNEL;
  const dir = env.MCP_SSO_BUNDLE_DIR;
  const file = typeof dir === "string" && dir.length > 0 ? join(dir, "cloudflare.json") : undefined;
  if (file !== undefined && existsSync(file)) {
    const value = readPrivateJson(file).tunnel_id;
    if (typeof value === "string" && value.length > 0) return value;
  }
  return undefined;
}

function spawnCapturing(command, args, env, timeoutMs) {
  const started = Date.now();
  const child = spawn(command, args, { cwd: REPO, env, stdio: ["ignore", "pipe", "pipe"] });
  const state = { child, stdout: "", stderr: "", exited: undefined, started };
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { if (state.stdout.length < MAX_CAPTURE) state.stdout += chunk; });
  child.stderr.on("data", (chunk) => { if (state.stderr.length < MAX_CAPTURE) state.stderr += chunk; });
  const timer = timeoutMs === undefined ? undefined : setTimeout(() => child.kill("SIGKILL"), timeoutMs);
  state.exit = new Promise((resolveExit) => {
    child.once("error", () => { if (timer) clearTimeout(timer); state.exited = { code: 1, signal: null }; state.stderr += "\nprocess could not be started"; resolveExit(state.exited); });
    child.once("exit", (code, signal) => { if (timer) clearTimeout(timer); state.exited = { code, signal }; resolveExit(state.exited); });
  });
  return state;
}

async function runRow(row, env, args) {
  const state = row.kind === "command"
    ? spawnCapturing(row.command[0], row.command.slice(1), env, ROW_TIMEOUT_MS)
    : spawnCapturing(join(REPO, "scripts/live/run.sh"), [row.entry, row.leg, ...args], env, ROW_TIMEOUT_MS);
  const { code, signal } = await state.exit;
  return {
    code: signal ? 1 : code, stdout: state.stdout, stderr: signal ? `${state.stderr}\nrow ${signal}` : state.stderr,
    durationMs: Date.now() - state.started,
  };
}

const answers = async (origin) => {
  try {
    const response = await fetch(`${origin}/.well-known/oauth-protected-resource`, { signal: AbortSignal.timeout(5_000), redirect: "manual" });
    return response.status === 200;
  } catch {
    return false;
  }
};
const sleep = (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms));

/** Bring the generation's legs up through serve.sh and wait until every
 *  public origin answers. Resolves to { serving } or to the row status the
 *  generation's rows all take. */
async function startServing(serve, env) {
  const infra = env.MCP_SSO_INFRA_DIR;
  const stack = env.MCP_SSO_CLOUDFLARE_STACK;
  let origins;
  try {
    const raw = execFileSync("./scripts/tofu-run.sh", [stack, "output", "-json", "issuer_origins"], { cwd: infra, env, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    origins = serve.legs.map((leg) => issuerOriginForLeg(raw, leg));
  } catch {
    return { status: "FAIL", reason: "serve_failed", note: "issuer origins are unavailable through the infrastructure wrapper" };
  }
  for (const origin of origins) {
    if (await answers(origin)) return { status: "BLOCKED", reason: "tunnel_already_served" };
  }
  const tunnel = tunnelId(env);
  if (tunnel === undefined) return { status: "BLOCKED", reason: "tunnel_credentials_absent" };
  const serving = spawnCapturing(join(REPO, "scripts/live/serve.sh"), serve.legs, { ...env, ...serve.env, MCP_SSO_TUNNEL: tunnel });
  const deadline = Date.now() + SERVE_READY_MS;
  while (Date.now() < deadline) {
    if (serving.exited !== undefined) {
      const failure = classifyServeFailure(serving.stderr);
      return { ...failure, note: `${serving.stdout}\n${serving.stderr}`.trim().split("\n").slice(-20).join("\n") };
    }
    const ready = await Promise.all(origins.map(answers));
    if (ready.every(Boolean)) return { serving };
    await sleep(2_000);
  }
  await stopServing(serving);
  return { status: "FAIL", reason: "serve_failed", note: "the served origins did not answer within the readiness budget" };
}

async function stopServing(serving) {
  if (serving.exited !== undefined) return;
  serving.child.kill("SIGTERM");
  const grace = setTimeout(() => serving.child.kill("SIGKILL"), 30_000);
  await serving.exit;
  clearTimeout(grace);
}

function git(args) {
  return execFileSync("git", ["-C", REPO, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
}

const options = parseArgs(process.argv.slice(2));
const rows = ROWS.filter((row) => options.rows === undefined || options.rows.has(row.id));
if (rows.length === 0) throw new Error("no rehearsal rows selected");
const runtimeCommit = git(["rev-parse", "HEAD"]);
const dirty = git(["status", "--porcelain", "--untracked-files=no"]).length > 0;
const secrets = collectPrivateValues(process.env);
const startedAt = new Date().toISOString();
const results = [];
// Driver results (an Access assertion is one) live here for the run, owner-only,
// and are removed on every exit path below.
const handoffDir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), "mcp-sso-rehearsal-"));
const provided = new Map();
const record = (row, status, reason, extra = {}) => {
  results.push({ ...row, mode: row.env.MCP_SSO_DCR_MODE, status, reason, durationMs: 0, lines: [], ...extra });
  process.stdout.write(`${status.padEnd(7)} ${row.id}${reason ? ` [${reason}]` : ""}\n`);
};
process.stdout.write(`rehearsal: runtime commit ${runtimeCommit}${dirty ? " (dirty tree)" : ""}, ${rows.length} rows\n`);
try {
  for (const generation of generations(rows)) {
    let serving;
    if (generation.serve !== undefined) {
      const started = await startServing(generation.serve, process.env);
      if (started.serving === undefined) {
        if (started.note) process.stdout.write(`${started.note.replace(/^/gm, "    ")}\n`);
        for (const row of generation.rows) record(row, started.status, started.reason);
        continue;
      }
      serving = started.serving;
    }
    for (const row of generation.rows) {
      const env = { ...process.env, ...row.env };
      const args = [...(row.args ?? [])];
      let outFile;
      if (row.kind === "driver") {
        outFile = join(handoffDir, `${row.id}.json`);
        args.push("--out", outFile);
      }
      if (row.kind === "client") env.MCP_SSO_AUDIT_FILE = join(REPO, ".live-state", row.leg, "audit.jsonl");
      if (row.needs !== undefined && provided.has(row.needs)) env[HANDOFF_ENV[row.needs]] = provided.get(row.needs);
      const run = await runRow(row, env, args);
      const outcome = row.kind === "driver" ? classifyDriverRun({ ...run, expect: row.expect })
        : row.kind === "command" ? classifyCommandRun(run) : classifyRun(run);
      let { lines, status, reason } = outcome;
      if (row.kind === "driver" && status !== "PASS" && outFile !== undefined && existsSync(outFile)) {
        // The driver's trace names page classes and steps, never a host or text;
        // it is what says where an unexpected sign-in stopped.
        try {
          const trace = readPrivateJson(outFile).trace;
          if (Array.isArray(trace)) lines = [...lines, { kind: "FAIL", text: `trace ${trace.filter((step) => typeof step === "string").join(" > ")}` }];
        } catch { /* the classification already stands */ }
      }
      const leaked = [...secrets].some((value) => run.stdout.includes(value) || run.stderr.includes(value));
      if (leaked) {
        status = "FAIL";
        reason = "private_value_in_output";
        lines = [{ kind: "FAIL", text: LEAK_NOTE }];
      }
      if (status === "PASS" && row.provides !== undefined) provided.set(row.provides, outFile);
      results.push({
        ...row, mode: row.env.MCP_SSO_DCR_MODE, status, reason, outcome: outcome.outcome, checks: outcome.checks,
        durationMs: run.durationMs, lines,
      });
      process.stdout.write(`${status.padEnd(7)} ${row.id}${reason ? ` [${reason}]` : ""} in ${Math.round(run.durationMs / 1000)}s\n`);
      if (status !== "PASS" && !leaked) {
        // The probes print fixed labels and run.sh prints fixed reasons; the tail
        // is bounded so a runaway child cannot flood the log.
        const tail = `${run.stdout}\n${run.stderr}`.trim().split("\n").slice(-40).join("\n");
        if (tail) process.stdout.write(`${tail.replace(/^/gm, "    ")}\n`);
      }
    }
    if (serving !== undefined) await stopServing(serving);
  }
} finally {
  rmSync(handoffDir, { recursive: true, force: true });
}
const receipt = buildReceipt({
  runtimeCommit, dirty, startedAt, finishedAt: new Date().toISOString(), rows: results,
  runner: process.env.GITHUB_RUN_ID ? `github-actions:${process.env.GITHUB_RUN_ID}` : "local",
});
mkdirSync(dirname(options.out), { recursive: true, mode: 0o700 });
writeFileSync(options.out, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(`\n${formatSummary(receipt)}\nreceipt: ${options.out}\n`);
process.exitCode = receipt.evidence ? 0 : 1;
