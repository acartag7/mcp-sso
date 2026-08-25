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
import { readGoogleCredentialFile } from "./run-support.mjs";
import { ROWS, buildReceipt, classifyDriverRun, classifyRun, formatSummary } from "./rehearsal-support.mjs";

const REPO = fileURLToPath(new URL("../..", import.meta.url));
const ROW_TIMEOUT_MS = 10 * 60_000;
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

function runRow(row, env, args) {
  return new Promise((resolveRow) => {
    const started = Date.now();
    const child = spawn(join(REPO, "scripts/live/run.sh"), [row.entry, row.leg, ...args], {
      cwd: REPO, env, stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { if (stdout.length < MAX_CAPTURE) stdout += chunk; });
    child.stderr.on("data", (chunk) => { if (stderr.length < MAX_CAPTURE) stderr += chunk; });
    const timer = setTimeout(() => child.kill("SIGKILL"), ROW_TIMEOUT_MS);
    child.once("error", () => { clearTimeout(timer); resolveRow({ code: 1, stdout, stderr: `${stderr}\nrun.sh could not be started`, durationMs: Date.now() - started }); });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      resolveRow({ code: signal ? 1 : code, stdout, stderr: signal ? `${stderr}\nrow ${signal}` : stderr, durationMs: Date.now() - started });
    });
  });
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
process.stdout.write(`rehearsal: runtime commit ${runtimeCommit}${dirty ? " (dirty tree)" : ""}, ${rows.length} rows\n`);
try {
  for (const row of rows) {
    const env = { ...process.env, ...row.env };
    const args = [...(row.args ?? [])];
    let outFile;
    if (row.kind === "driver") {
      outFile = join(handoffDir, `${row.id}.json`);
      args.push("--out", outFile);
    }
    if (row.needs !== undefined && provided.has(row.needs)) env[HANDOFF_ENV[row.needs]] = provided.get(row.needs);
    const run = await runRow(row, env, args);
    const outcome = row.kind === "driver" ? classifyDriverRun({ ...run, expect: row.expect }) : classifyRun(run);
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
