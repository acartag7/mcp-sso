// Pure support for scripts/live/rehearsal.mjs: the row list, the outcome
// classifier, the receipt shape, and the summary. Nothing here spawns a
// process or touches the network, so every decision the orchestrator makes is
// testable without a provider.

/** The rows one rehearsal runs, in order. Each is one run.sh invocation. */
export const ROWS = Object.freeze([
  { id: "probe-entra", entry: "scripts/live/probe-entra.mjs", leg: "entra", env: {} },
  { id: "probe-google", entry: "scripts/live/probe-google.mjs", leg: "google", env: {} },
  { id: "probe-cloudflare", entry: "scripts/live/probe-cloudflare.mjs", leg: "cloudflare_access", env: {} },
  { id: "probe-e2e:stored", entry: "scripts/live/probe-e2e.mjs", leg: "entra", env: { MCP_SSO_DCR_MODE: "stored" } },
  { id: "probe-e2e:stateless", entry: "scripts/live/probe-e2e.mjs", leg: "entra", env: { MCP_SSO_DCR_MODE: "stateless" } },
]);

/** A row is BLOCKED, not FAILED, only when run.sh refused it for one of these
 *  owner-armable reasons. The patterns are run.sh's own fixed messages; every
 *  other non-zero exit is a FAIL. A BLOCKED row is never evidence and still
 *  turns the rehearsal red; it exists so the summary names what to arm. */
const BLOCKED_REASONS = Object.freeze([
  { reason: "cloudflare_access_login_required", pattern: /cloudflared (?:could not mint|returned an empty|is required to mint)/ },
  { reason: "google_credentials_absent", pattern: /Google credential file must be/ },
  { reason: "infrastructure_session_expired", pattern: /(?:AWS|Azure) session is not valid/ },
]);

const LINE = /^(PASS|FAIL|CONTROL)  (.*)$/;
const SUMMARIES = [
  { pattern: /^(\d+)\/(\d+) (?:live )?checks passed$/m, read: (m) => ({ passed: +m[1], total: +m[2], controls: 0 }) },
  { pattern: /^(\d+) live checks passed; (\d+) local controls passed$/m, read: (m) => ({ passed: +m[1], total: undefined, controls: +m[2] }) },
];

/** Classify one run.sh outcome from its exit code and captured output. */
export function classifyRun({ code, stdout, stderr }) {
  const lines = stdout.split("\n").map((line) => LINE.exec(line)).filter(Boolean)
    .map((match) => ({ kind: match[1], text: match[2] }));
  const failed = lines.filter((line) => line.kind === "FAIL").length;
  let checks;
  for (const summary of SUMMARIES) {
    const match = summary.pattern.exec(stdout);
    if (match) checks = summary.read(match);
  }
  if (code !== 0) {
    for (const { reason, pattern } of BLOCKED_REASONS) {
      if (pattern.test(stderr) && lines.length === 0) return { status: "BLOCKED", reason, lines, checks };
    }
    return { status: "FAIL", reason: lines.length === 0 ? "runner_refused" : "checks_failed", lines, checks };
  }
  if (failed > 0) return { status: "FAIL", reason: "checks_failed", lines, checks };
  if (checks === undefined || lines.length === 0) return { status: "FAIL", reason: "no_summary", lines, checks };
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

/** The receipt. Row output is kept only when it carries no private value;
 *  a leak turns the row into a FAIL whose lines are replaced by a fixed note. */
export function buildReceipt({ runtimeCommit, dirty, startedAt, finishedAt, rows, runner }) {
  const evidence = dirty !== true && rows.every((row) => row.status === "PASS");
  return {
    schema: 1,
    kind: "mcp-sso-release-rehearsal",
    runtimeCommit,
    dirty: dirty === true,
    evidence,
    runner,
    startedAt,
    finishedAt,
    rows: rows.map((row) => ({
      id: row.id, entry: row.entry, leg: row.leg, mode: row.mode, status: row.status, reason: row.reason,
      checks: row.checks, durationMs: row.durationMs, lines: row.lines,
    })),
  };
}

/** Human summary for the job log. One line per row, then the verdict. */
export function formatSummary(receipt) {
  const out = [];
  for (const row of receipt.rows) {
    const checks = row.checks
      ? ` (${row.checks.passed}${row.checks.total !== undefined ? `/${row.checks.total}` : ""} checks${row.checks.controls ? `, ${row.checks.controls} controls` : ""})`
      : "";
    out.push(`${row.status.padEnd(7)} ${row.id}${row.reason ? ` [${row.reason}]` : ""}${checks}`);
  }
  const counts = { PASS: 0, FAIL: 0, BLOCKED: 0 };
  for (const row of receipt.rows) counts[row.status]++;
  out.push("");
  out.push(`rehearsal at ${receipt.runtimeCommit}${receipt.dirty ? " (DIRTY TREE, not evidence)" : ""}: `
    + `${counts.PASS} passed, ${counts.FAIL} failed, ${counts.BLOCKED} blocked; evidence=${receipt.evidence}`);
  return out.join("\n");
}
