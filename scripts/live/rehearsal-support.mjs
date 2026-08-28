// Pure support for scripts/live/rehearsal.mjs: the row list, the outcome
// classifiers, the receipt shape, and the summary. Nothing here spawns a
// process or touches the network, so every decision the orchestrator makes is
// testable without a provider.

const DRIVER = "scripts/live/drive-identity.mjs";
const CLIENT = "scripts/live/probe-client.mjs";
const CLI = "scripts/live/probe-cli.mjs";
/** Served generations. Rows that share one run inside one serve.sh lifetime.
 *  The two deny generations restart the Entra leg with a deliberately wrong
 *  operator value through run.sh's marked channels (CHECKLIST rows D4, D5). */
const SERVE_MAIN = Object.freeze({ legs: ["cloudflare_access", "entra"], env: {} });
const SERVE_WRONG_TENANT = Object.freeze({ legs: ["entra"], env: { MCP_SSO_ENTRA_ALLOWED_TENANT_IDS: "00000000-0000-0000-0000-000000000001" } });
const SERVE_NOT_ALLOWLISTED = Object.freeze({ legs: ["entra"], env: { MCP_SSO_ENTRA_SUBJECT_ALLOWLIST: "00000000-0000-0000-0000-000000000002" } });
const client = (id, leg, user, expect, serve) => ({ id, kind: "client", entry: CLIENT, leg, env: {}, args: ["--user", user, "--expect", expect], serve });
const cli = (id, leg, which, serve) => ({ id, kind: "client", entry: CLI, leg, env: {}, args: ["--cli", which, "--user", "member"], serve });

/** The rows one rehearsal runs, in order. Each is one run.sh invocation
 *  (or, for the `command` kind, one repository command). A `driver` row signs
 *  a test user in through the real provider pages and must end in exactly
 *  `expect`; a row that `provides` something hands its result file to the
 *  later row that `needs` it; a `client` row runs against a leg serve.sh
 *  exposes for the rows that share its `serve` generation. */
export const ROWS = Object.freeze([
  { id: "release-matrix", kind: "command", command: ["pnpm", "run", "test:release"], env: {} },
  { id: "probe-entra", kind: "probe", entry: "scripts/live/probe-entra.mjs", leg: "entra", env: {} },
  { id: "probe-google", kind: "probe", entry: "scripts/live/probe-google.mjs", leg: "google", env: {} },
  { id: "access-login", kind: "driver", entry: DRIVER, leg: "cloudflare_access", env: {},
    args: ["cloudflare-assertion", "--user", "member"], expect: "approved", provides: "cloudflare-assertion" },
  { id: "access-edge-denial", kind: "driver", entry: DRIVER, leg: "cloudflare_access", env: {},
    args: ["cloudflare-assertion", "--user", "nogroups"], expect: "denied_at_access_edge" },
  { id: "probe-cloudflare", kind: "probe", entry: "scripts/live/probe-cloudflare.mjs", leg: "cloudflare_access", env: {},
    needs: "cloudflare-assertion" },
  { id: "probe-e2e:stored", kind: "probe", entry: "scripts/live/probe-e2e.mjs", leg: "entra", env: { MCP_SSO_DCR_MODE: "stored" } },
  { id: "probe-e2e:stateless", kind: "probe", entry: "scripts/live/probe-e2e.mjs", leg: "entra", env: { MCP_SSO_DCR_MODE: "stateless" } },
  client("client-entra:member", "entra", "member", "approved", SERVE_MAIN),
  client("client-entra:nogroups", "entra", "nogroups", "entra_no_groups", SERVE_MAIN),
  client("client-entra:wronggroup", "entra", "wronggroup", "entra_no_mapped_groups", SERVE_MAIN),
  client("client-entra:overage", "entra", "overage", "entra_groups_overage", SERVE_MAIN),
  client("client-cloudflare:member", "cloudflare_access", "member", "approved", SERVE_MAIN),
  cli("claude-code:entra", "entra", "claude", SERVE_MAIN),
  cli("claude-code:cloudflare", "cloudflare_access", "claude", SERVE_MAIN),
  cli("codex-cli:entra", "entra", "codex", SERVE_MAIN),
  cli("codex-cli:cloudflare", "cloudflare_access", "codex", SERVE_MAIN),
  client("client-entra:wrong-tenant", "entra", "member", "entra_bad_tid", SERVE_WRONG_TENANT),
  client("client-entra:not-allowlisted", "entra", "member", "entra_subject_not_allowed", SERVE_NOT_ALLOWLISTED),
]);

/** What a row that `needs` a provided result receives it through. An
 *  unknown handoff is an error, never a silently unset variable. */
export const HANDOFF_ENV = Object.freeze({ "cloudflare-assertion": "MCP_SSO_CF_ACCESS_ASSERTION_FILE" });

/** Group consecutive rows by the serve generation they share. Rows without a
 *  generation stand alone. Order is preserved. */
export function generations(rows) {
  const groups = [];
  for (const row of rows) {
    const last = groups[groups.length - 1];
    if (last !== undefined && last.serve !== undefined && last.serve === row.serve) last.rows.push(row);
    else groups.push({ serve: row.serve, rows: [row] });
  }
  return groups;
}

/** A row is BLOCKED, not FAILED, only when it was refused for one of these
 *  owner-armable reasons. The patterns are run.sh's and the probes' own fixed
 *  refusal messages, matched on stderr only when nothing else ran; every other
 *  non-zero exit is a FAIL. A BLOCKED row is never evidence and still turns
 *  the rehearsal red; it exists so the summary names what to arm. */
const BLOCKED_REASONS = Object.freeze([
  { reason: "cloudflare_access_login_required", pattern: /cloudflared (?:could not mint|returned an empty|is required to mint)/ },
  { reason: "google_credentials_absent", pattern: /Google credential file must be/ },
  { reason: "infrastructure_session_expired", pattern: /(?:AWS|Azure) session is not valid/ },
  { reason: "browser_unavailable", pattern: /^probe-(?:client|cli): browser is unavailable/m },
  // A client row whose driver met an operator-armable outcome refuses at
  // runner level, so the row records that reason instead of a failed check.
  { reason: "blocked_mfa_interstitial", pattern: /^probe-(?:client|cli): blocked_mfa_interstitial$/m },
  { reason: "browser_not_local", pattern: /^probe-cli: the CLI rows need a browser on this host/m },
  { reason: "cli_unavailable", pattern: /^probe-cli: (?:claude|codex|python3) is unavailable on PATH/m },
]);
/** Driver outcomes an operator can arm: a browser to run in, an MFA-free test user. */
const BLOCKED_OUTCOMES = new Set(["browser_unavailable", "blocked_mfa_interstitial"]);
/** Outcomes the driver exits 0 for; any other outcome must come with a non-zero exit. */
const DEFINITE_DRIVER_OUTCOMES = new Set(["approved", "denied_at_access_edge", "denied_at_login", "denied_at_gateway"]);
const SERVE_BLOCKED = Object.freeze([
  { reason: "tunnel_credentials_absent", pattern: /tunnel credentials file is missing|MCP_SSO_TUNNEL/ },
  { reason: "cloudflared_unavailable", pattern: /cloudflared is required/ },
]);
/** Every BLOCKED reason the rehearsal can record, for the records that list them. */
export const BLOCKED_REASON_NAMES = Object.freeze([
  ...BLOCKED_REASONS.map((entry) => entry.reason), ...BLOCKED_OUTCOMES, "release_services_absent",
  "tunnel_already_served", ...SERVE_BLOCKED.map((entry) => entry.reason), "prerequisite_row_did_not_pass",
]);

/** A probe's own report. `NOTE` carries what the row observed rather than what
 *  it checked — the client version a CLI row ran, the audit sequence, a skipped
 *  tool call — and the receipt has to keep it: `record-receipt.mjs` reads the
 *  client version from exactly these lines, and a driver row already records
 *  its trace as a NOTE. Only the other three kinds are checks, so every
 *  "did this row run any checks" decision counts those. */
const LINE = /^(PASS|FAIL|CONTROL|NOTE)  (.*)$/;
const SUMMARIES = [
  { pattern: /^(\d+)\/(\d+) (?:live )?checks passed$/m, read: (m) => ({ passed: +m[1], total: +m[2], controls: 0 }) },
  { pattern: /^(\d+) live checks passed; (\d+) local controls passed$/m, read: (m) => ({ passed: +m[1], total: undefined, controls: +m[2] }) },
];

function blockedReason(stderr) {
  for (const { reason, pattern } of BLOCKED_REASONS) if (pattern.test(stderr)) return reason;
  return undefined;
}

/** Classify one probe outcome from its exit code and captured output. */
export function classifyRun({ code, stdout, stderr }) {
  const lines = stdout.split("\n").map((line) => LINE.exec(line)).filter(Boolean)
    .map((match) => ({ kind: match[1], text: match[2] }));
  const checkLines = lines.filter((line) => line.kind !== "NOTE");
  const failed = lines.filter((line) => line.kind === "FAIL").length;
  let checks;
  for (const summary of SUMMARIES) {
    const match = summary.pattern.exec(stdout);
    if (match) checks = summary.read(match);
  }
  if (code !== 0) {
    const reason = blockedReason(stderr);
    if (reason !== undefined && checkLines.length === 0) return { status: "BLOCKED", reason, lines, checks };
    return { status: "FAIL", reason: checkLines.length === 0 ? "runner_refused" : "checks_failed", lines, checks };
  }
  if (failed > 0) return { status: "FAIL", reason: "checks_failed", lines, checks };
  if (checks === undefined || checkLines.length === 0) return { status: "FAIL", reason: "no_summary", lines, checks };
  if (checks.passed <= 0) return { status: "FAIL", reason: "no_checks", lines, checks };
  if (checks.total !== undefined && checks.passed !== checks.total) {
    return { status: "FAIL", reason: "summary_mismatch", lines, checks };
  }
  const passLines = lines.filter((line) => line.kind === "PASS").length;
  const controlLines = lines.filter((line) => line.kind === "CONTROL").length;
  if (passLines !== checks.passed || controlLines !== checks.controls) {
    return { status: "FAIL", reason: "summary_mismatch", lines, checks };
  }
  return { status: "PASS", lines, checks };
}

/** Classify the release-matrix command: every RM row passed, or the services
 *  it needs were not there (BLOCKED, only when the runner refused before any
 *  row ran), or it failed. */
export function classifyCommandRun({ code, stdout, stderr }) {
  const summary = /^PASS release matrix: (\d+)\/(\d+) required rows$/m.exec(stdout);
  const rowLines = stdout.split("\n").map((line) => /^(PASS|FAIL) (RM\.\d+) (.*)$/.exec(line)).filter(Boolean)
    .map((match) => ({ kind: match[1], text: `${match[2]} ${match[3]}` }));
  const failed = rowLines.filter((line) => line.kind === "FAIL").length;
  if (code !== 0 && rowLines.length === 0
    && /^release matrix preflight failed: (?:MYSQL_URL|REDIS_URL|RUN_INTEGRATION=true) is required/m.test(stderr)) {
    return { status: "BLOCKED", reason: "release_services_absent", lines: [] };
  }
  if (code === 0 && summary !== null && failed === 0 && +summary[1] === +summary[2] && +summary[1] > 0 && rowLines.length === +summary[1]) {
    return { status: "PASS", lines: rowLines, checks: { passed: +summary[1], total: +summary[2], controls: 0 } };
  }
  return { status: "FAIL", reason: failed > 0 ? "checks_failed" : "matrix_failed", lines: rowLines };
}

/** Classify one driver outcome: the last `outcome:` line against `expect`,
 *  and the exit code against the outcome (a definite outcome exits 0; a
 *  process that died after printing one is not a pass). */
export function classifyDriverRun({ code, stdout, stderr, expect }) {
  const matches = [...stdout.matchAll(/^outcome: ([a-z_]+)$/gm)];
  if (matches.length === 0) {
    const reason = blockedReason(stderr);
    if (reason !== undefined && code !== 0) return { status: "BLOCKED", reason, lines: [] };
    return { status: "FAIL", reason: "runner_refused", lines: [] };
  }
  const outcome = matches[matches.length - 1][1];
  const lines = [{ kind: outcome === expect ? "PASS" : "FAIL", text: `sign-in outcome ${outcome}, expected ${expect}` }];
  if (DEFINITE_DRIVER_OUTCOMES.has(outcome) !== (code === 0)) {
    return { status: "FAIL", reason: "driver_exit_mismatch", outcome, lines: [{ kind: "FAIL", text: `outcome ${outcome} with exit ${code}` }] };
  }
  if (outcome === expect) return { status: "PASS", outcome, lines };
  if (BLOCKED_OUTCOMES.has(outcome)) return { status: "BLOCKED", reason: outcome, outcome, lines };
  return { status: "FAIL", reason: `outcome_${outcome}`, outcome, lines };
}

/** Why a serve generation could not start: armable reasons are BLOCKED. */
export function classifyServeFailure(stderr) {
  for (const { reason, pattern } of SERVE_BLOCKED) if (pattern.test(stderr)) return { status: "BLOCKED", reason };
  return { status: "FAIL", reason: "serve_failed" };
}

/** The receipt. `complete` says whether every row in ROWS ran; `evidence`
 *  requires that, a clean tree, and every row PASS. Row output is kept only
 *  when it carries no private value; a leak turns the row into a FAIL whose
 *  lines are replaced by a fixed note. */
export function buildReceipt({ runtimeCommit, dirty, startedAt, finishedAt, rows, runner, totalRows = ROWS.length }) {
  const complete = rows.length === totalRows;
  const evidence = complete && rows.length > 0 && dirty !== true && rows.every((row) => row.status === "PASS");
  return {
    schema: 1,
    kind: "mcp-sso-release-rehearsal",
    runtimeCommit,
    dirty: dirty === true,
    complete,
    evidence,
    runner,
    startedAt,
    finishedAt,
    rows: rows.map((row) => ({
      id: row.id, kind: row.kind, entry: row.entry, leg: row.leg, mode: row.mode, status: row.status, reason: row.reason,
      outcome: row.outcome, checks: row.checks, durationMs: row.durationMs, lines: row.lines,
    })),
  };
}

/** Human summary for the job log. One line per row, then the verdict. */
export function formatSummary(receipt) {
  const out = [];
  for (const row of receipt.rows) {
    const checks = row.checks
      ? ` (${row.checks.passed}${row.checks.total !== undefined ? `/${row.checks.total}` : ""} checks${row.checks.controls ? `, ${row.checks.controls} controls` : ""})`
      : row.outcome ? ` (${row.outcome})` : "";
    out.push(`${row.status.padEnd(7)} ${row.id}${row.reason ? ` [${row.reason}]` : ""}${checks}`);
  }
  const counts = { PASS: 0, FAIL: 0, BLOCKED: 0 };
  for (const row of receipt.rows) counts[row.status]++;
  out.push("");
  out.push(`rehearsal at ${receipt.runtimeCommit}${receipt.dirty ? " (DIRTY TREE, not evidence)" : ""}`
    + `${receipt.complete ? "" : " (PARTIAL, not evidence)"}: `
    + `${counts.PASS} passed, ${counts.FAIL} failed, ${counts.BLOCKED} blocked; evidence=${receipt.evidence}`);
  return out.join("\n");
}
