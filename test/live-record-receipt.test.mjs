// Recording turns a passing rehearsal receipt into the evidence the gate reads.
// What matters is that it refuses everything that is not evidence, and that the
// document it writes is one the gate accepts.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { evaluateReleaseReadiness } from "../scripts/lib/release-ready.mjs";
import {
  assertClientVersions, assertReachableFrom, assertRecordedAtHead, provenMatrixRows, readRehearsalReceipt, toEvidence,
  writeActiveReceipt,
} from "../scripts/live/record-receipt.mjs";
import { DRIVEN_ROWS, ROWS } from "../scripts/live/rehearsal-support.mjs";

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

test("BEHAVIOUR record-receipt: a campaign supersedes the one before it, and a failed one leaves nothing behind", () => {
  // A second active receipt would leave the older one failing freshness
  // forever: its commit predates the change the new run recorded.
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-receipt-"));
  try {
    const path = join(dir, "release.json");
    const first = `${JSON.stringify({ runtimeCommit: COMMIT, recordedAt: "2026-08-27T00:00:00.000Z" })}\n`;
    assert.equal(writeActiveReceipt(path, first), null, "the first recording supersedes nothing");
    const archived = writeActiveReceipt(path, `${JSON.stringify({ runtimeCommit: "b".repeat(40) })}\n`);
    assert.ok(archived?.includes(`release-${COMMIT.slice(0, 7)}-20260827T0000`), "the one it replaces is archived under its own campaign");
    assert.equal(readFileSync(archived, "utf8"), first, "moved, not deleted");
    assert.match(readFileSync(path, "utf8"), /bbbbbbb/, "and the new one is active");

    // Recording the same run again is a correction, not a campaign. It carries
    // the same runtimeCommit and recordedAt, and archiving it would put a
    // document in archive/ that was never a campaign, which the checklist then
    // has the operator commit as history.
    const run = { runtimeCommit: "c".repeat(40), recordedAt: "2026-08-28T00:00:00.000Z" };
    writeFileSync(path, `${JSON.stringify({ ...run, rows: ["typo"] })}\n`);
    const archivedBefore = readdirSync(join(dir, "archive")).length;
    assert.equal(writeActiveReceipt(path, `${JSON.stringify({ ...run, rows: ["fixed"] })}\n`), null,
      "a re-record of the same run archives nothing");
    assert.equal(readdirSync(join(dir, "archive")).length, archivedBefore, "and leaves the archive as it was");
    assert.match(readFileSync(path, "utf8"), /fixed/, "while the correction becomes the active receipt");

    // A different run at the same commit is still a campaign, and is archived.
    const later = writeActiveReceipt(path, `${JSON.stringify({ ...run, recordedAt: "2026-08-28T09:00:00.000Z" })}\n`);
    assert.ok(later, "a second campaign against the same commit is archived, not replaced");

    // A name already taken belongs to a campaign that ran, so the next one
    // moves aside rather than replacing it.
    writeFileSync(path, first);
    const second = writeActiveReceipt(path, "{}\n");
    assert.ok(second.endsWith("-2.json"), `a taken name is not overwritten: ${second}`);

    // A recording that fails leaves the evidence set exactly as it was: the
    // active receipt still active, and no staged file to make the next
    // rehearsal record a dirty tree and refuse itself as evidence.
    //
    // The failure is injected as a file where the archive directory belongs,
    // which fails for any user. File permissions would not: a suite running as
    // root, as it does in many containers, renames into a mode 0500 directory
    // quite happily and the test would fail on correct code.
    const before = readFileSync(path, "utf8");
    rmSync(join(dir, "archive"), { recursive: true, force: true });
    writeFileSync(join(dir, "archive"), "not a directory\n");
    assert.throws(() => writeActiveReceipt(path, "{}\n"), "an archive directory that cannot exist fails the recording");
    assert.equal(readFileSync(path, "utf8"), before, "the active receipt is untouched");
    assert.equal(existsSync(`${path}.staged`), false, "and no staged file is left behind");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("BEHAVIOUR record-receipt: the first receipt is staged too, so a failed write cannot truncate it", () => {
  // The active receipt is only ever created by a rename. A direct write to it
  // can fail part-way and leave a truncated document that every later gate run
  // fails to parse, and there is no previous receipt to roll back to.
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-receipt-"));
  try {
    const path = join(dir, "release.json");
    // Staging cannot succeed, so nothing may reach the active receipt.
    mkdirSync(`${path}.staged`);
    assert.throws(() => writeActiveReceipt(path, "{}\n"), "a failed staging fails the recording");
    assert.equal(existsSync(path), false, "and the active receipt was never written directly");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  const gate = readFileSync(new URL("../scripts/check-release-ready.mjs", import.meta.url), "utf8");
  assert.match(gate, /name\.endsWith\("\.json"\)/, "the gate reads documents, so the archive directory is not one");
});

test("BEHAVIOUR record-receipt: what it writes is what the gate accepts", () => {
  const evidence = toEvidence(readRehearsalReceipt(receiptFor()), { source: "https://example.invalid/run", driven: [...DRIVEN_ROWS] });
  assert.equal(evidence.schema, 1);
  assert.equal(evidence.complete, true);
  assert.equal(evidence.rows.length, ROWS.length + DRIVEN_ROWS.length);
  assert.ok(evidence.rows.every((row) => ["id", "status", "observed"].includes(Object.keys(row)[0]) && row.id && row.status));

  // A CLI row's client version is an observation, and the record keeps it.
  const withVersion = receiptFor();
  withVersion.rows.find((r) => r.id === "claude-code:entra").lines = [
    { kind: "NOTE", text: "claude 2.1.247" }, { kind: "PASS", text: "not an observation" },
  ];
  const recorded = toEvidence(readRehearsalReceipt(withVersion), { driven: [...DRIVEN_ROWS] });
  assert.deepEqual(recorded.rows.find((r) => r.id === "claude-code:entra").observed, ["claude 2.1.247"],
    "the version the run observed reaches the record, and a check line does not");

  // The generated value itself goes through the gate, not a static file beside
  // it: dropping releaseMatrix from toEvidence must fail here rather than leave
  // the workflow producing an artifact nothing accepts.
  // The generated value itself goes through the gate, not a static file beside
  // it: dropping releaseMatrix from toEvidence must fail here rather than leave
  // the recorder producing a document nothing accepts.
  const head = execFileSync("git", ["-C", ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const generated = toEvidence(readRehearsalReceipt(receiptFor({ runtimeCommit: head })), { driven: [...DRIVEN_ROWS] });
  const accepted = evaluateReleaseReadiness({
    packageJson: { version: "0.5.0", exports: { ".": {} } },
    releaseMatrix: { rows: [{ id: "RM.1", title: "Root", packedArtifact: true, exports: ["."], evidence: [{ file: "test/a.test.ts", name: "a" }] }] },
    receipts: { "release.json": generated },
    gitCwd: ROOT, releaseCommit: "HEAD",
  });
  assert.deepEqual(accepted.errors, [], "the gate accepts exactly what the recorder writes, hand-driven rows included");
  assert.deepEqual(generated.rows.filter((row) => row.driven).map((row) => row.id), [...DRIVEN_ROWS],
    "and the rows a person drove are in the same document, marked as driven");

  // A campaign that skipped the hosted connectors is not a campaign: without
  // this the gate would authorize a release on the automated half alone.
  assert.throws(() => toEvidence(readRehearsalReceipt(receiptFor()), { driven: [] }),
    /missing 7 hand-driven row\(s\)/, "no hand-driven rows is not a complete campaign");
  assert.throws(() => toEvidence(readRehearsalReceipt(receiptFor()), { driven: DRIVEN_ROWS.slice(1) }),
    /missing 1 hand-driven row\(s\): A3/, "and neither is a partial one");
  assert.throws(() => toEvidence(readRehearsalReceipt(receiptFor()), { driven: [...DRIVEN_ROWS, "F2s"] }),
    /not a hand-driven checklist row/, "an invented row cannot stand in for one that was never driven");

  // A hand-driven row cannot restate a machine-checked one: that would record a
  // person's word for something a probe already decides.
  assert.throws(() => toEvidence(readRehearsalReceipt(receiptFor()), { driven: ["release-matrix", ...DRIVEN_ROWS] }),
    /machine-checked/, "a machine-checked row cannot be claimed by hand");
  assert.throws(() => toEvidence(readRehearsalReceipt(receiptFor()), { driven: ["C1", ...DRIVEN_ROWS] }),
    /named twice/, "and a hand-driven row cannot be named twice");
});

test("BEHAVIOUR record-receipt: a campaign recorded off the release line is refused where it can still be fixed", () => {
  // The gate needs the receipt's commit to be an ancestor of the release. A
  // squash merge keeps no branch commit, so a campaign run on the release
  // branch passes on the pull request head and fails on main, after the merge
  // has thrown that commit away. Refuse it at recording time instead.
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-reach-"));
  const git = (...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" }).trim();
  try {
    git("init", "-q", "-b", "main");
    git("config", "user.email", "t@example.invalid");
    git("config", "user.name", "T");
    writeFileSync(join(dir, "f"), "a\n");
    git("add", "-A");
    git("commit", "-qm", "base");
    const base = git("rev-parse", "HEAD");
    git("switch", "-qc", "release-branch");
    git("commit", "--allow-empty", "-qm", "bump");
    const onBranch = git("rev-parse", "HEAD");

    assert.equal(assertReachableFrom(base, { cwd: dir, ref: "main" }), base, "a commit on the line is accepted");
    assert.throws(() => assertReachableFrom(onBranch, { cwd: dir, ref: "main" }), /not an ancestor of main/,
      "a commit only on the release branch is refused");
    // Fail closed: no reachable ref is a refusal, never a pass.
    assert.throws(() => assertReachableFrom(base, { cwd: dir, ref: "origin/main" }), /cannot resolve origin\/main/,
      "and an absent ref is refused rather than skipped");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("BEHAVIOUR record-receipt: one campaign is one checkout, unmodified", () => {
  // The rehearsal records the commit it ran at, but the rows a person drives
  // run against whatever serve.sh is serving. A checkout moved in between would
  // file those rows under a commit whose code they never exercised, and the
  // gate would authorize the release on them.
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-head-"));
  const git = (...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" }).trim();
  try {
    git("init", "-q", "-b", "main");
    git("config", "user.email", "t@example.invalid");
    git("config", "user.name", "T");
    writeFileSync(join(dir, "f"), "a\n");
    git("add", "-A");
    git("commit", "-qm", "campaign");
    const campaign = git("rev-parse", "HEAD");
    assert.equal(assertRecordedAtHead(campaign, { cwd: dir }), campaign, "recording where the campaign ran is fine");

    // An uncommitted edit is the same defect without moving HEAD: serve.sh
    // serves the working tree and, unlike run.sh, never checks it.
    writeFileSync(join(dir, "f"), "edited\n");
    assert.throws(() => assertRecordedAtHead(campaign, { cwd: dir }), /uncommitted changes/,
      "an edit on top of the campaign commit is refused");
    writeFileSync(join(dir, "f"), "a\n");
    assert.equal(assertRecordedAtHead(campaign, { cwd: dir }), campaign, "and reverting it is enough");

    // The recorder's own output is not something the rows ran against. Counting
    // it would refuse the second write of one campaign, and committing to clear
    // it moves HEAD, which the check above refuses: recordable exactly once.
    mkdirSync(join(dir, "docs/evidence/archive"), { recursive: true });
    writeFileSync(join(dir, "docs/evidence/release.json"), "{}\n");
    writeFileSync(join(dir, "docs/evidence/archive/release-old.json"), "{}\n");
    assert.equal(assertRecordedAtHead(campaign, { cwd: dir }), campaign,
      "a receipt already written here does not block recording again");

    git("commit", "--allow-empty", "-qm", "moved on");
    assert.throws(() => assertRecordedAtHead(campaign, { cwd: dir }), /but the checkout is now/,
      "a checkout moved between the rehearsal and the hand-driven rows is refused");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
