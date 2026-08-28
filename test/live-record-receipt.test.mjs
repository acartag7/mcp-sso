// Recording turns a passing rehearsal receipt into the evidence the gate reads.
// What matters is that it refuses everything that is not evidence, and that the
// document it writes is one the gate accepts.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { evaluateReleaseReadiness } from "../scripts/lib/release-ready.mjs";
import { assertClientVersions, provenMatrixRows, readRehearsalReceipt, toEvidence } from "../scripts/live/record-receipt.mjs";
import { ROWS } from "../scripts/live/rehearsal-support.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const COMMIT = "a".repeat(40);
const receiptFor = (overrides = {}) => ({
  kind: "mcp-sso-release-rehearsal", schema: 1, runtimeCommit: COMMIT, dirty: false, complete: true, evidence: true,
  startedAt: "s", finishedAt: "f",
  rows: ROWS.map((row) => ({
    id: row.id, status: "PASS",
    lines: row.id === "release-matrix" ? [{ kind: "PASS", text: "RM.1 Packed exports (1 evidence item)" }] : [],
  })),
  ...overrides,
});

test("BEHAVIOUR record-receipt: only a complete, passing receipt on a clean tree is evidence", () => {
  assert.equal(readRehearsalReceipt(receiptFor()).runtimeCommit, COMMIT);
  const refused = [
    [{ kind: "something-else" }, /not a rehearsal receipt/],
    [{ schema: 2 }, /not a rehearsal receipt/],
    [{ runtimeCommit: "abc" }, /no full runtime commit/],
    [{ dirty: true }, /does not record a clean tree/],
    [{ dirty: undefined }, /does not record a clean tree/],
    [{ dirty: "yes" }, /does not record a clean tree/],
    [{ crashed: "stopped" }, /did not finish/],
    [{ interrupted: "signal" }, /did not finish/],
    [{ complete: false }, /--rows subset is never evidence/],
    [{ evidence: false }, /not evidence/],
    [{ rows: receiptFor().rows.slice(1) }, /partial: 1 row\(s\)/],
    [{ rows: [...receiptFor().rows, { id: "invented", status: "PASS" }] }, /a row the rehearsal does not define/],
    [{ rows: [receiptFor().rows[0], receiptFor().rows[0]] }, /repeats a row|partial/],
    [{ rows: receiptFor().rows.map((r, i) => (i === 2 ? { ...r, status: "FAIL" } : r)) }, /1 row\(s\) did not pass/],
  ];
  for (const [override, pattern] of refused) {
    assert.throws(() => readRehearsalReceipt(receiptFor(override)), pattern, JSON.stringify(override).slice(0, 60));
  }
});

test("BEHAVIOUR record-receipt: a CLI row must name the client version it ran", () => {
  const versioned = receiptFor();
  for (const row of versioned.rows) {
    if (row.id.startsWith("claude-code:")) row.lines = [{ kind: "NOTE", text: "claude 2.1.247" }];
    if (row.id.startsWith("codex-cli:")) row.lines = [{ kind: "NOTE", text: "codex 0.150.1" }];
  }
  assert.equal(assertClientVersions(versioned), versioned);
  const missing = structuredClone(versioned);
  missing.rows.find((row) => row.id === "codex-cli:entra").lines = [];
  assert.throws(() => assertClientVersions(missing), /codex-cli:entra does not name the codex version/);
  const wrongShape = structuredClone(versioned);
  wrongShape.rows.find((row) => row.id === "claude-code:entra").lines = [{ kind: "NOTE", text: "claude unknown" }];
  assert.throws(() => assertClientVersions(wrongShape), /claude-code:entra does not name the claude version/);
  const notANote = structuredClone(versioned);
  notANote.rows.find((row) => row.id === "claude-code:entra").lines = [{ kind: "PASS", text: "claude 2.1.247" }];
  assert.throws(() => assertClientVersions(notANote), /does not name the claude version/, "a check line is not an observation");
});

test("BEHAVIOUR record-receipt: the release-matrix rows come from the row that ran them", () => {
  assert.deepEqual(provenMatrixRows(receiptFor()), ["RM.1"]);
  const failed = receiptFor();
  failed.rows.find((r) => r.id === "release-matrix").lines = [{ kind: "FAIL", text: "RM.1 Packed exports" }];
  assert.deepEqual(provenMatrixRows(failed), [], "a row that did not pass covers no export");
  const noise = receiptFor();
  noise.rows.find((r) => r.id === "release-matrix").lines = [
    { kind: "PASS", text: "RM.2 Fastify" }, { kind: "NOTE", text: "RM.9 not a check" }, { kind: "PASS", text: "not an id" },
  ];
  assert.deepEqual(provenMatrixRows(noise), ["RM.2"], "only passing lines that name a row count");
});

test("BEHAVIOUR record-receipt: a campaign supersedes the one before it", () => {
  // Two receipts for the same producer would leave the older one failing
  // freshness forever: its commit predates the change the new run recorded.
  const source = readFileSync(new URL("../scripts/live/record-receipt.mjs", import.meta.url), "utf8");
  assert.match(source, /docs\/evidence\/rehearsal\.json/, "the active receipt has one name");
  assert.match(source, /rehearsal-\$\{String\(previous\.runtimeCommit\)\.slice\(0, 7\)\}-\$\{stamp\}/, "and the one it replaces is archived under its own campaign");
  assert.match(source, /renameSync\(path, archive\)/, "moved, not deleted");
  // The replacement is written before anything moves, and a failed move is
  // rolled back: a recording that fails must leave the evidence set as it was,
  // not with the active receipt gone.
  assert.ok(source.indexOf("writeFileSync(staged, body)") < source.indexOf("renameSync(path, archive)"),
    "the replacement is staged before the active receipt moves");
  assert.match(source, /catch \(error\) \{\s*renameSync\(archive, path\);\s*throw error;/,
    "and a failed swap puts the archived receipt back");
  assert.match(source, /for \(let n = 2; existsSync\(archive\); n\+\+\)/,
    "and a name already taken belongs to a campaign that ran, so the new one moves aside instead of replacing it");
  const gate = readFileSync(new URL("../scripts/check-release-ready.mjs", import.meta.url), "utf8");
  assert.match(gate, /name\.endsWith\("\.json"\)/, "the gate reads documents, so the archive directory is not one");
});

test("BEHAVIOUR record-receipt: what it writes is what the gate accepts", () => {
  const evidence = toEvidence(readRehearsalReceipt(receiptFor()), { source: "https://example.invalid/run" });
  assert.equal(evidence.schema, 1);
  assert.equal(evidence.producer, "rehearsal");
  assert.equal(evidence.complete, true);
  assert.equal(evidence.rows.length, ROWS.length);
  assert.ok(evidence.rows.every((row) => ["id", "status", "observed"].includes(Object.keys(row)[0]) && row.id && row.status));

  // A CLI row's client version is an observation, and the record keeps it.
  const withVersion = receiptFor();
  withVersion.rows.find((r) => r.id === "claude-code:entra").lines = [
    { kind: "NOTE", text: "claude 2.1.247" }, { kind: "PASS", text: "not an observation" },
  ];
  const recorded = toEvidence(readRehearsalReceipt(withVersion));
  assert.deepEqual(recorded.rows.find((r) => r.id === "claude-code:entra").observed, ["claude 2.1.247"],
    "the version the run observed reaches the record, and a check line does not");

  // The generated value itself goes through the gate, not a static file beside
  // it: dropping releaseMatrix from toEvidence must fail here rather than leave
  // the workflow producing an artifact nothing accepts.
  const head = execFileSync("git", ["-C", ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const generated = toEvidence(readRehearsalReceipt(receiptFor({ runtimeCommit: head })));
  const onlyGenerated = evaluateReleaseReadiness({
    packageJson: { version: "0.5.0", exports: { ".": {} } },
    releaseMatrix: { rows: [{ id: "RM.1", title: "Root", packedArtifact: true, exports: ["."], evidence: [{ file: "test/a.test.ts", name: "a" }] }] },
    receipts: {
      "rehearsal.json": generated,
      "operator.json": { schema: 1, producer: "operator", runtimeCommit: head, recordedAt: "x", complete: true, rows: [{ id: "F2", status: "PASS" }] },
    },
    gitCwd: ROOT, releaseCommit: "HEAD",
  });
  assert.deepEqual(onlyGenerated.errors, [], "the gate accepts exactly what the recorder writes");

  // The committed receipts name commits from earlier campaigns, so this part
  // needs the history a release checkout has. Ordinary CI clones shallow, and
  // the release flow is where the gate actually runs: the publish build checks
  // out full history before it calls check:release-ready.
  const shallow = execFileSync("git", ["-C", ROOT, "rev-parse", "--is-shallow-repository"], { encoding: "utf8" }).trim() === "true";
  if (shallow) return;
  const receipts = Object.fromEntries(["rehearsal.json", "operator.json"]
    .map((name) => [name, JSON.parse(readFileSync(new URL(`../docs/evidence/${name}`, import.meta.url), "utf8"))]));
  const result = evaluateReleaseReadiness({
    packageJson: JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")),
    releaseMatrix: JSON.parse(readFileSync(new URL("../test/release-matrix.json", import.meta.url), "utf8")),
    receipts,
    gitCwd: ROOT, releaseCommit: "HEAD",
  });
  assert.deepEqual(result.errors, [], "the repository's own evidence satisfies its own gate");
  // Only a rehearsal receipt covers exports, and only through its own passing
  // release-matrix row.
  const forged = { ...receipts["operator.json"], releaseMatrix: ["RM.1"] };
  const claimed = evaluateReleaseReadiness({ ...result, packageJson: { version: "0.5.0", exports: { ".": {} } },
    releaseMatrix: { rows: [{ id: "RM.1", title: "Root", packedArtifact: true, exports: ["."], evidence: [{ file: "a", name: "b" }] }] },
    receipts: { "rehearsal.json": receipts["rehearsal.json"], "operator.json": forged },
    gitCwd: ROOT, releaseCommit: "HEAD" });
  assert.ok(claimed.errors.some((e) => e.includes("cannot carry release-matrix rows")), "an operator receipt cannot mint coverage");
});
