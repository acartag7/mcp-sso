// The release rehearsal: every live row, in order, through run.sh, with one
// receipt at the end. It runs the same way on a laptop (MCP_SSO_INFRA_DIR at the
// private infrastructure checkout) and in CI (MCP_SSO_INFRA_DIR at
// scripts/live/ci/infra with a fetched bundle); this file does not know which.
//
//   node scripts/live/rehearsal.mjs [--out <receipt.json>] [--rows id,id,...]
//
// Exit 0 only when every row in ROWS ran and passed on a clean tree. A
// `--rows` subset is a working receipt (`complete: false`), never evidence. A
// BLOCKED row names what an operator must arm; it is never a pass.
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { constants, homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { credentialValues, leaksPrivateValue, privateValues, readPrivateJson } from "./ci/bundle-support.mjs";
import { issuerOriginForLeg, readClientKeysFile, readGoogleCredentialFile } from "./run-support.mjs";
import {
  HANDOFF_ENV, ROWS, buildReceipt, classifyCommandRun, classifyDriverRun, classifyRun, classifyServeFailure, formatSummary, generations,
} from "./rehearsal-support.mjs";

const REPO = fileURLToPath(new URL("../..", import.meta.url));
const ROW_TIMEOUT_MS = 10 * 60_000;
const SERVE_READY_MS = 120_000;
const MAX_CAPTURE = 1024 * 1024;
const LEAK_NOTE = "output withheld: a private value from the run configuration appeared in it";
/** Every credential the job itself holds: the assumed AWS session, and the
 *  runner's own tokens, with which a child could mint a fresh OIDC token for
 *  the `live` environment or write to the run's artifacts. */
const JOB_CREDENTIAL_KEYS = [
  "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
  "AWS_CREDENTIAL_EXPIRATION", "AWS_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
  "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_RUNTIME_TOKEN",
  "GITHUB_TOKEN", "GH_TOKEN",
];
/** The only variables a repository command (the release matrix) receives: the
 *  services it tests against, and the package-manager and runner configuration
 *  pnpm needs to find its store and metadata cache. It never holds the AWS
 *  session, the bundle location, or a provider value. */
const COMMAND_ENV_KEYS = ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "CI", "NO_COLOR", "RUN_INTEGRATION", "MYSQL_URL", "REDIS_URL"];
const COMMAND_ENV_PREFIXES = ["PNPM_", "npm_config_", "COREPACK_", "XDG_", "GITHUB_", "RUNNER_"];
const commandEnv = (env) => Object.fromEntries(Object.entries(env).filter(([key]) =>
  !JOB_CREDENTIAL_KEYS.includes(key)
  && (COMMAND_ENV_KEYS.includes(key) || COMMAND_ENV_PREFIXES.some((prefix) => key.startsWith(prefix)))));
/** With the bundle adapter in use, every provider value has already been read
 *  from disk and no child needs a credential of the job's: not run.sh, not the
 *  served application, and certainly not the tunnel connector, which would
 *  otherwise hold a session that can read the whole `/mcp-sso/live/*` set, and
 *  the means to mint a new one, for as long as a generation is served. They
 *  are removed from every child there. On a laptop the wrapper reads the
 *  stacks live, so the AWS session is kept. */
function childEnv(env) {
  if (typeof env.MCP_SSO_BUNDLE_DIR !== "string" || env.MCP_SSO_BUNDLE_DIR.length === 0) return env;
  const copy = { ...env };
  for (const key of JOB_CREDENTIAL_KEYS) delete copy[key];
  return copy;
}

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
 *  the Google credential file at the same path run.sh resolves; values the run
 *  itself produces (a captured Access assertion) are added as they appear. */
function collectPrivateValues(env, collect = privateValues) {
  const values = new Set();
  const dir = env.MCP_SSO_BUNDLE_DIR;
  if (typeof dir === "string" && dir.length > 0 && existsSync(dir)) {
    for (const name of readdirSync(dir)) if (name.endsWith(".json")) collect(readPrivateJson(join(dir, name)), values);
  } else {
    // The laptop path: the same values live in the stacks rather than in a
    // bundle, and the scanner must know them there too, or a row that echoed
    // a client secret or a test password locally would not be caught. Read
    // once, through the same wrapper run.sh uses; a session that cannot answer
    // leaves the run to fail on its first stack read, with nothing scanned yet.
    for (const stack of [env.MCP_SSO_ENTRA_STACK, env.MCP_SSO_CLOUDFLARE_STACK]) {
      if (typeof stack !== "string" || stack.length === 0) continue;
      try {
        const raw = execFileSync("./scripts/tofu-run.sh", [stack, "output", "-json"], {
          cwd: env.MCP_SSO_INFRA_DIR, env, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 120_000,
        });
        // `tofu output -json` answers {name: {value, type, sensitive}}: the
        // output's own name is the key, so the credential keys classify the
        // same way they do when the value comes from a bundle.
        for (const [name, output] of Object.entries(JSON.parse(raw))) collect(output?.value, values, name);
      } catch { /* the first stack read of the run reports this properly */ }
    }
  }
  const googleEnv = env.MCP_SSO_GOOGLE_ENV || join(env.HOME ?? homedir(), ".mcp-sso-google.env");
  if (existsSync(googleEnv)) collect(readGoogleCredentialFile(googleEnv), values);
  const clientKeys = env.MCP_SSO_CLIENT_KEYS_FILE;
  if (typeof clientKeys === "string" && clientKeys.length > 0 && existsSync(clientKeys)) collect(readClientKeysFile(clientKeys), values);
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

const sleep = (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms));

/** Ask a child's whole process group to stop, then kill what is left. run.sh
 *  execs a Node probe that owns a browser, a pseudo-terminal and a private
 *  HOME, and serve.sh supervises the tunnel and the example servers: signalling
 *  the group is what reaches them, and SIGTERM first is what lets each clean up
 *  after itself. Every stop in this file goes through here, so the timeout, an
 *  interrupt and the teardown all end a child the same way. */
async function stopChild(state, graceMs) {
  if (state === undefined || state.exited !== undefined) return;
  const signalGroup = (signal) => {
    try {
      process.kill(-state.child.pid, signal);
    } catch {
      try { state.child.kill(signal); } catch { /* already gone */ }
    }
  };
  const groupAlive = () => {
    try {
      process.kill(-state.child.pid, 0);
      return true;
    } catch {
      return false;
    }
  };
  signalGroup("SIGTERM");
  const deadline = Date.now() + graceMs;
  // Bounded: a leader that ignores SIGTERM must not hold the run open until
  // the job's own timeout. Whatever the leader does, the group is checked and
  // escalated when the budget runs out.
  await Promise.race([state.exit, sleep(graceMs)]);
  // A process group outlives its leader: the browser or the CLI a probe
  // started can still be in it after run.sh has gone. Wait for the group
  // itself, and escalate to the group when the budget runs out.
  while (Date.now() < deadline && groupAlive()) await sleep(200);
  if (groupAlive()) {
    signalGroup("SIGKILL");
    const hard = Date.now() + 5_000;
    while (Date.now() < hard && groupAlive()) await sleep(200);
  }
}

/** Spawn with both streams captured. Every chunk is scanned for a private
 *  value as it arrives, before the capture is bounded, so a leak past the
 *  bound still marks the run. The child leads its own process group, so it can
 *  be stopped with everything it started. */
function spawnCapturing(command, args, env, timeoutMs, secrets) {
  const started = Date.now();
  const child = spawn(command, args, { cwd: REPO, env, stdio: ["ignore", "pipe", "pipe"], detached: true });
  const state = { child, stdout: "", stderr: "", leaked: false, exited: undefined, timedOut: false, started };
  const scan = (chunk) => { if (!state.leaked && leaksPrivateValue(chunk, secrets)) state.leaked = true; };
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { scan(chunk); if (state.stdout.length < MAX_CAPTURE) state.stdout += chunk; });
  child.stderr.on("data", (chunk) => { scan(chunk); if (state.stderr.length < MAX_CAPTURE) state.stderr += chunk; });
  const timer = timeoutMs === undefined ? undefined : setTimeout(() => { state.timedOut = true; stopChild(state, 15_000); }, timeoutMs);
  state.exit = new Promise((resolveExit) => {
    child.once("error", () => { if (timer) clearTimeout(timer); state.exited = { code: 1, signal: null }; state.stderr += "\nprocess could not be started"; resolveExit(state.exited); });
    child.once("exit", (code, signal) => { if (timer) clearTimeout(timer); state.exited = { code, signal }; resolveExit(state.exited); });
  });
  return state;
}

async function runRow(row, env, args, secrets, hold) {
  const state = row.kind === "command"
    ? spawnCapturing(row.command[0], row.command.slice(1), commandEnv(env), ROW_TIMEOUT_MS, secrets)
    : spawnCapturing(join(REPO, "scripts/live/run.sh"), [row.entry, row.leg, ...args], childEnv(env), ROW_TIMEOUT_MS, secrets);
  hold?.(state);
  const { code, signal } = await state.exit;
  hold?.(undefined);
  const leaked = state.leaked || leaksPrivateValue(`${state.stdout}\n${state.stderr}`, secrets);
  return {
    code: signal ? 1 : code, stdout: state.stdout, stderr: signal ? `${state.stderr}\nrow ${signal}` : state.stderr,
    durationMs: Date.now() - state.started, leaked,
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

/** Bring the generation's legs up through serve.sh and wait until every
 *  public origin answers. Resolves to { serving } or to the row status the
 *  generation's rows all take. A note is printed only when it carries no
 *  private value. */
async function startServing(serve, env, secrets, hold) {
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
  const serving = spawnCapturing(join(REPO, "scripts/live/serve.sh"), serve.legs, childEnv({ ...env, ...serve.env, MCP_SSO_TUNNEL: tunnel }), undefined, secrets);
  // Published before the readiness wait, so an interrupt during startup can
  // stop this child instead of waiting out the readiness budget.
  hold?.(serving);
  const deadline = Date.now() + SERVE_READY_MS;
  while (Date.now() < deadline) {
    if (serving.exited !== undefined) {
      const failure = classifyServeFailure(serving.stderr);
      const tail = `${serving.stdout}\n${serving.stderr}`.trim().split("\n").slice(-20).join("\n");
      return { ...failure, note: serving.leaked || leaksPrivateValue(tail, secrets) ? LEAK_NOTE : tail };
    }
    const ready = await Promise.all(origins.map(answers));
    if (ready.every(Boolean)) return { serving };
    await sleep(2_000);
  }
  await stopServing(serving, servedSecrets);
  return { status: "FAIL", reason: "serve_failed", note: "the served origins did not answer within the readiness budget" };
}

/** Stop the generation's servers and report whether the serve process printed
 *  a CREDENTIAL at any point in its life. A leak from a server that stayed
 *  healthy is only visible here, after shutdown: the readiness check above sees
 *  the process only while it is starting. */
async function stopServing(serving, credentials) {
  if (serving === undefined) return false;
  await stopChild(serving, 30_000);
  return credentials !== undefined && leaksPrivateValue(`${serving.stdout}\n${serving.stderr}`, credentials);
}

function git(args) {
  return execFileSync("git", ["-C", REPO, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
}

const options = parseArgs(process.argv.slice(2));
const rows = ROWS.filter((row) => options.rows === undefined || options.rows.has(row.id));
if (rows.length === 0) throw new Error("no rehearsal rows selected");
const selected = new Set(rows.map((row) => row.id));
const runtimeCommit = git(["rev-parse", "HEAD"]);
const dirty = git(["status", "--porcelain", "--untracked-files=no"]).length > 0;
const secrets = collectPrivateValues(process.env);
// serve.sh prints the public origins it brings up, which are private values but
// not credentials, so the served process is scanned against the credential
// subset only: the question there is whether a credential escaped into the
// served application's own output, not whether the deployment named itself.
const servedSecrets = collectPrivateValues(process.env, credentialValues);
// serve.sh names the tunnel it was told to run, in its banner and in the
// connector configuration path, so the id the harness itself handed it is not
// evidence of a leak. Every other credential still fails the run.
const servedTunnel = tunnelId(process.env);
if (servedTunnel !== undefined) servedSecrets.delete(servedTunnel);
const startedAt = new Date().toISOString();
const results = [];
// Driver results (an Access assertion is one) live here for the run, owner-only,
// and are removed on every exit path: the finally below and the signal handlers.
const handoffDir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), "mcp-sso-rehearsal-"));
// Every row child's TMPDIR. A probe's private HOME, its keychain file and its
// CLI configuration are made with mkdtemp under it, so whatever a probe cannot
// clean up itself, because a timeout or a signal ended it before its `finally`
// ran, is removed with this directory when the run ends.
const scratchDir = join(handoffDir, "scratch");
mkdirSync(scratchDir, { mode: 0o700 });
const provided = new Map();
let serving;
const served = [];
let running;
const teardown = async () => {
  // The row's own child first: it holds the browser and the CLI session. It is
  // asked to stop, then killed if it does not.
  await stopChild(running, 5_000);
  await stopServing(serving, servedSecrets);
  serving = undefined;
  rmSync(handoffDir, { recursive: true, force: true });
};
// An interrupted run still writes its receipt, marked interrupted and never
// evidence, so the operator and the workflow artifact have a record of how far
// it got; the process then exits with the signal's own status.
let interrupted;
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.once(signal, () => {
    interrupted = signal;
    // End the children now rather than waiting for the row to finish or time
    // out, but end them the way a shutdown does: serve.sh terminates
    // cloudflared and the example servers from its own EXIT and TERM traps,
    // which a SIGKILL would skip, orphaning the tunnel. SIGTERM here, and the
    // teardown below escalates if a child ignores it.
    for (const state of [running, serving]) void stopChild(state, 5_000);
  });
}
const record = (row, status, reason, extra = {}) => {
  results.push({ ...row, mode: row.env.MCP_SSO_DCR_MODE, status, reason, durationMs: 0, lines: [], ...extra });
  process.stdout.write(`${status.padEnd(7)} ${row.id}${reason ? ` [${reason}]` : ""}\n`);
};
process.stdout.write(`rehearsal: runtime commit ${runtimeCommit}${dirty ? " (dirty tree)" : ""}, ${rows.length} of ${ROWS.length} rows\n`);
let crashed;
try {
  for (const generation of generations(rows)) {
    if (interrupted !== undefined) break;
    if (generation.serve !== undefined) {
      const started = await startServing(generation.serve, process.env, secrets, (state) => { serving = state; });
      if (started.serving === undefined) {
        // startServing already stopped whatever it had started; drop the
        // published handle so the teardown does not try to stop it again.
        serving = undefined;
        if (started.note) process.stdout.write(`${started.note.replace(/^/gm, "    ")}\n`);
        for (const row of generation.rows) record(row, started.status, started.reason);
        continue;
      }
      serving = started.serving;
    }
    for (const row of generation.rows) {
      const env = { ...process.env, ...row.env, TMPDIR: scratchDir };
      const args = [...(row.args ?? [])];
      let outFile;
      if (row.kind === "driver") {
        outFile = join(handoffDir, `${row.id}.json`);
        args.push("--out", outFile);
      }
      if (row.kind === "client") env.MCP_SSO_AUDIT_FILE = join(REPO, ".live-state", row.leg, "audit.jsonl");
      if (row.needs !== undefined) {
        const channel = HANDOFF_ENV[row.needs];
        if (channel === undefined) throw new Error(`no handoff channel for ${row.needs}`);
        const provider = ROWS.find((candidate) => candidate.provides === row.needs);
        if (provided.has(row.needs)) env[channel] = provided.get(row.needs);
        else if (provider !== undefined && selected.has(provider.id)) {
          // The providing row ran and did not pass: this row must not fall back
          // to an operator's own credential and read as proof of the driver.
          record(row, "BLOCKED", "prerequisite_row_did_not_pass");
          continue;
        }
      }
      if (interrupted !== undefined) break;
      const run = await runRow(row, env, args, secrets, (state) => { running = state; });
      const outcome = row.kind === "driver" ? classifyDriverRun({ ...run, expect: row.expect })
        : row.kind === "command" ? classifyCommandRun(run) : classifyRun(run);
      let { lines, status, reason } = outcome;
      if (row.kind === "driver" && outFile !== undefined && existsSync(outFile)) {
        // The driver's trace names page classes and steps, never a host or text;
        // it is recorded on every outcome, so a passing denial row shows that the
        // account reached the edge rather than stopping at the login.
        try {
          const result = readPrivateJson(outFile);
          if (Array.isArray(result.trace)) lines = [...lines, { kind: "NOTE", text: `trace ${result.trace.filter((step) => typeof step === "string").join(" > ")}` }];
          if (typeof result.assertion === "string") secrets.add(result.assertion);
        } catch { /* the classification already stands */ }
      }
      if (run.leaked) {
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
      if (status !== "PASS" && !run.leaked) {
        // The probes print fixed labels and run.sh prints fixed reasons; the tail
        // is bounded so a runaway child cannot flood the log.
        const tail = `${run.stdout}\n${run.stderr}`.trim().split("\n").slice(-40).join("\n");
        if (tail) process.stdout.write(`${tail.replace(/^/gm, "    ")}\n`);
      }
    }
    // A served leg that printed a private value is a failure of the run even
    // when every row passed: the leak is only observable once the process has
    // been stopped and its whole output is in hand.
    if (await stopServing(serving, servedSecrets)) {
      served.push({ id: `serve:${generation.serve?.legs.join("+") ?? "leg"}`, kind: "serve", entry: "scripts/live/serve.sh", leg: generation.rows[0]?.leg ?? "", env: {} });
    }
    serving = undefined;
  }
} catch (error) {
  crashed = error;
} finally {
  await teardown();
}
for (const row of served) record(row, "FAIL", "private_value_in_output", { lines: [{ kind: "FAIL", text: LEAK_NOTE }] });
const receipt = buildReceipt({
  runtimeCommit, dirty, startedAt, finishedAt: new Date().toISOString(), rows: results,
  runner: process.env.GITHUB_RUN_ID ? `github-actions:${process.env.GITHUB_RUN_ID}` : "local",
});
if (crashed !== undefined) {
  receipt.evidence = false;
  receipt.crashed = "the rehearsal stopped before every selected row ran";
}
if (interrupted !== undefined) {
  receipt.evidence = false;
  receipt.interrupted = interrupted;
}
// The receipt is the one output that leaves the machine; nothing private may
// be in it, whatever a row's own scan concluded.
if (leaksPrivateValue(JSON.stringify(receipt), [...secrets])) {
  for (const row of receipt.rows) row.lines = [{ kind: "FAIL", text: LEAK_NOTE }];
  receipt.evidence = false;
}
mkdirSync(dirname(options.out), { recursive: true, mode: 0o700 });
writeFileSync(options.out, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(`\n${formatSummary(receipt)}\nreceipt: ${options.out}\n`);
if (crashed !== undefined) process.stdout.write(`rehearsal stopped early: ${crashed?.constructor?.name ?? "error"}\n`);
if (interrupted !== undefined) {
  // The receipt is written and every child is stopped; exit the way the signal
  // would have, so a shell and CI see the interruption for what it was.
  process.stdout.write(`rehearsal interrupted by ${interrupted}\n`);
  process.exit(128 + (constants.signals[interrupted] ?? 15));
}
process.exitCode = receipt.evidence ? 0 : 1;
