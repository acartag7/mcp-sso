// Behavioural coverage for scripts/live/render-evidence.mjs: a passing receipt
// renders provider and export rows that the release-readiness parser accepts
// at the receipt's commit; anything less is refused.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { evaluateReleaseReadiness } from "../scripts/lib/release-ready.mjs";
import { PROVIDER_ROWS, readReceipt, render } from "../scripts/live/render-evidence.mjs";
import { ROWS, classifyCommandRun } from "../scripts/live/rehearsal-support.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const packageJson = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const releaseMatrix = JSON.parse(readFileSync(join(ROOT, "test/release-matrix.json"), "utf8"));
const status = readFileSync(join(ROOT, "docs/verification-status.md"), "utf8");
const HEAD = execFileSync("git", ["-C", ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
// The real document's structure with its recorded rows replaced by one row at
// HEAD, so the round trip does not depend on commits a shallow checkout lacks.
const SENTINEL_ROW = `| Entra ID | claude.ai custom connector | CIMD flow | Verified | 2026-08-19 | Runtime commit \`${HEAD}\`. |`;
const document = (() => {
  const lines = readFileSync(join(ROOT, "docs/client-compatibility.md"), "utf8").split("\n");
  const start = lines.indexOf("| Provider | Client | Flow driven | Status | Date | Limits |") + 2;
  let end = start;
  while (end < lines.length && lines[end].startsWith("|")) end += 1;
  assert.ok(start > 1 && end > start, "the real document has a provider table");
  return [...lines.slice(0, start), SENTINEL_ROW, ...lines.slice(end)].join("\n");
})();

const receiptFor = (ids, extra = {}) => ({
  schema: 1, kind: "mcp-sso-release-rehearsal", runtimeCommit: HEAD, dirty: false, evidence: true, runner: "local",
  startedAt: "s", finishedAt: "f", rows: ids.map((id) => ({ id, status: "PASS", lines: [] })), ...extra,
});
const ALL = ROWS.map((row) => row.id);

test("BEHAVIOUR render-evidence: a full receipt renders every provider row and the export table at the receipt's commit", () => {
  const rendered = render({ document, receipt: receiptFor(ALL), date: "2026-08-25", packageJson, releaseMatrix });
  const check = evaluateReleaseReadiness({ packageJson, releaseMatrix, compatibility: rendered, status, gitCwd: ROOT, releaseCommit: HEAD });
  assert.deepEqual(check.errors, [], "the gate's own parser accepts the rendered document");
  assert.ok(check.staleEvidence.every((stale) => stale.commit !== HEAD), "nothing the receipt recorded is stale at its own commit");
  for (const row of PROVIDER_ROWS) assert.match(rendered, new RegExp(`^\\| ${row.provider} \\| ${row.client.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} \\|.*\\| ${row.status} \\| 2026-08-25 \\| Runtime commit \`${HEAD}\`\\.`, "m"));
  for (const name of Object.keys(packageJson.exports)) assert.match(rendered, new RegExp(`^\\| \`${name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}\` \\| .* \\| \`${HEAD}\` \\|$`, "m"));
  assert.match(rendered, /\| Google \| Provider probe, driven by the rehearsal \| .* \| Verified with limit \| 2026-08-25 \| Runtime commit `[0-9a-f]{40}`\. Limit: the Google sign-in was not driven\. \|/);
  assert.equal((rendered.match(/^\| Entra ID \| Rehearsal deny fixtures \|/gm) ?? []).length, 1);
  const again = render({ document: rendered, receipt: receiptFor(ALL), date: "2026-08-26", packageJson, releaseMatrix });
  assert.equal((again.match(/^\| Entra ID \| Rehearsal deny fixtures \|/gm) ?? []).length, 1, "re-rendering replaces the subject rather than duplicating it");
  assert.match(again, /\| Rehearsal deny fixtures \| .* \| 2026-08-26 \|/);
  assert.equal((rendered.match(/^\| Entra ID \| claude\.ai custom connector \|/gm) ?? []).length, 1, "rows the rehearsal did not drive are kept");
});

test("BEHAVIOUR render-evidence: a partial receipt renders only what it proved and touches no export row", () => {
  const partial = receiptFor(ALL.filter((id) => id !== "release-matrix" && id !== "client-entra:overage"));
  const rendered = render({ document, receipt: partial, date: "2026-08-25", packageJson, releaseMatrix });
  assert.doesNotMatch(rendered, /Rehearsal deny fixtures \|.*2026-08-25/, "a deny row is written only when every fixture passed");
  assert.match(rendered, /Official MCP SDK client, driven by the rehearsal \|.*2026-08-25/);
  const exportLines = rendered.split("\n").filter((line) => line.startsWith("| `./"));
  assert.ok(exportLines.length > 0 && exportLines.every((line) => !line.includes(HEAD)), "without the release-matrix row the export table keeps its recorded commit");
  assert.throws(() => render({ document, receipt: receiptFor(["probe-entra"]), date: "2026-08-25", packageJson, releaseMatrix }), /proves no provider row/);
  assert.throws(() => render({ document, receipt: receiptFor(ALL), date: "25-08-2026", packageJson, releaseMatrix }), /YYYY-MM-DD/);
  assert.throws(() => render({ document: "# no tables\n", receipt: receiptFor(ALL), date: "2026-08-25", packageJson, releaseMatrix }), /table not found/);
});

test("BEHAVIOUR render-evidence: only an evidence receipt with a full commit is read", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-receipt-"));
  try {
    const file = join(dir, "receipt.json");
    const write = (value) => writeFileSync(file, JSON.stringify(value));
    write(receiptFor(ALL));
    assert.equal(readReceipt(file).runtimeCommit, HEAD);
    write(receiptFor(ALL, { evidence: false }));
    assert.throws(() => readReceipt(file), /not evidence/);
    write(receiptFor(ALL, { runtimeCommit: HEAD.slice(0, 7) }));
    assert.throws(() => readReceipt(file), /full runtime commit/);
    write({ kind: "other" });
    assert.throws(() => readReceipt(file), /not a rehearsal receipt/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("BEHAVIOUR rehearsal-support: the release-matrix command row passes only on a complete matrix", () => {
  const stdout = "PASS RM.1 Packed (1 evidence item)\nPASS RM.2 Fastify (1 evidence item)\n\nPASS release matrix: 2/2 required rows\n";
  const pass = classifyCommandRun({ code: 0, stdout, stderr: "" });
  assert.equal(pass.status, "PASS");
  assert.deepEqual(pass.checks, { passed: 2, total: 2, controls: 0 });
  assert.equal(pass.lines.length, 2);
  assert.equal(classifyCommandRun({ code: 1, stdout: "PASS RM.1 a (1 evidence item)\nFAIL RM.2 b: x [fail]\n", stderr: "" }).reason, "checks_failed");
  assert.equal(classifyCommandRun({ code: 0, stdout: "PASS RM.1 a (1 evidence item)\n", stderr: "" }).reason, "matrix_failed", "no summary is no pass");
  assert.equal(classifyCommandRun({ code: 0, stdout: "PASS RM.1 a (1 evidence item)\n\nPASS release matrix: 2/2 required rows\n", stderr: "" }).reason, "matrix_failed", "the summary must match the rows");
  assert.equal(classifyCommandRun({ code: 1, stdout: "", stderr: "release matrix preflight failed: MYSQL_URL is required; MySQL rows never skip\n" }).reason, "release_services_absent");
  assert.equal(ROWS[0].id, "release-matrix");
  assert.deepEqual(ROWS[0].command, ["pnpm", "run", "test:release"]);
});
