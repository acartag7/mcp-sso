// Turn a passing rehearsal receipt into the release evidence the gate reads
// (§15): one JSON document under docs/evidence/, naming the commit the campaign
// ran against and what it observed.
//
//   node scripts/live/record-receipt.mjs --receipt <receipt.json> [--row <id>]... [--write]
//
// Without --write the document goes to stdout. A receipt that is not evidence,
// a partial run, a dirty tree, or a failed row, is refused: the rehearsal
// already decided that, and this never second-guesses it into a pass.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DRIVEN_ROWS, ROWS } from "./rehearsal-support.mjs";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));

/** Re-derive from the receipt's own rows everything the caller would otherwise
 *  be trusting it to have summarised: the exact row set, once each, all passed.
 *  A truncated or hand-edited receipt cannot assert its own completeness. */
export function readRehearsalReceipt(receipt, expectedRows = ROWS.map((row) => row.id)) {
  if (receipt?.kind !== "mcp-sso-release-rehearsal" || receipt.schema !== 1) throw new Error("not a rehearsal receipt");
  if (!/^[0-9a-f]{40}$/.test(receipt.runtimeCommit ?? "")) throw new Error("the receipt names no full runtime commit");
  if (receipt.dirty !== false) throw new Error("the receipt does not record a clean tree");
  if (receipt.crashed !== undefined || receipt.interrupted !== undefined) throw new Error("the rehearsal did not finish");
  const rows = Array.isArray(receipt.rows) ? receipt.rows : [];
  const ids = rows.map((row) => row?.id);
  const missing = expectedRows.filter((id) => !ids.includes(id));
  if (missing.length > 0) throw new Error(`the receipt is partial: ${missing.length} row(s) of the rehearsal are absent`);
  if (ids.some((id) => !expectedRows.includes(id))) throw new Error("the receipt holds a row the rehearsal does not define");
  if (new Set(ids).size !== ids.length) throw new Error("the receipt repeats a row");
  const failed = rows.filter((row) => row?.status !== "PASS");
  if (failed.length > 0) throw new Error(`the receipt is not evidence: ${failed.length} row(s) did not pass`);
  if (receipt.complete !== true) throw new Error("the receipt is partial: a --rows subset is never evidence");
  if (receipt.evidence !== true) throw new Error("the receipt is not evidence: a row failed or was blocked, or the tree was dirty");
  return receipt;
}

/** The release-matrix rows the run proved, read from the row that ran them. A
 *  released export is covered by one of these, so an unreadable line is left
 *  out rather than guessed at. */
export function provenMatrixRows(receipt) {
  const row = receipt.rows.find((candidate) => candidate.id === "release-matrix");
  return (row?.lines ?? []).flatMap((line) => {
    const match = line?.kind === "PASS" && /^(RM\.\d+) /.exec(line.text ?? "");
    return match ? [match[1]] : [];
  });
}

/** What a row observed rather than what it checked: the client version a CLI
 *  row ran, the audit sequence, a skipped tool call. The gate does not read
 *  these, and a person does, which is why they are recorded rather than
 *  summarised away. */
export function observationsOf(row) {
  return (row.lines ?? []).flatMap((line) => (line?.kind === "NOTE" && typeof line.text === "string" ? [line.text] : []));
}

/** Rows whose evidence includes which build of a third-party client ran. The
 *  page this evidence feeds tells a reader that one Codex version failed a
 *  callback another completed, so a row without its version cannot be read. */
const CLIENT_VERSIONS = Object.freeze([
  { prefix: "claude-code:", cli: "claude" },
  { prefix: "codex-cli:", cli: "codex" },
]);

/** Refuse a receipt whose CLI row observed no version. The rehearsal prints it
 *  as a NOTE; a receipt that lost it would record a client flow nobody can
 *  attribute to a build. */
export function assertClientVersions(receipt) {
  for (const row of receipt.rows) {
    const expected = CLIENT_VERSIONS.find(({ prefix }) => String(row.id).startsWith(prefix));
    if (expected === undefined) continue;
    const named = observationsOf(row).some((text) => new RegExp(`^${expected.cli} \\d+\\.\\d+\\.\\d+$`).test(text));
    if (!named) throw new Error(`row ${row.id} does not name the ${expected.cli} version it ran`);
  }
  return receipt;
}

/** The evidence document, in the schema the gate reads. One campaign: the rows
 *  the rehearsal machine-checked, plus the rows a person drove against the same
 *  served leg, which no probe can drive. */
export function toEvidence(receipt, { source, driven = [] } = {}) {
  const machineChecked = new Set(receipt.rows.map((row) => row.id));
  for (const id of driven) {
    if (machineChecked.has(id)) throw new Error(`row ${id} is machine-checked; it cannot also be recorded by hand`);
    // Unknown is refused, not counted: a readable id that is not a checklist
    // row would otherwise stand in for one that was never driven.
    if (!DRIVEN_ROWS.includes(id)) throw new Error(`row ${id} is not a hand-driven checklist row (${DRIVEN_ROWS.join(", ")})`);
  }
  if (new Set(driven).size !== driven.length) throw new Error("a hand-driven row is named twice");
  const undriven = DRIVEN_ROWS.filter((id) => !driven.includes(id));
  if (undriven.length > 0) {
    throw new Error(`the campaign is missing ${undriven.length} hand-driven row(s): ${undriven.join(", ")}`);
  }
  return {
    schema: 1,
    runtimeCommit: receipt.runtimeCommit,
    recordedAt: receipt.finishedAt ?? receipt.startedAt,
    ...(source === undefined ? {} : { source }),
    complete: true,
    rows: [
      ...receipt.rows.map((row) => {
        const observed = observationsOf(row);
        return { id: row.id, status: row.status, ...(observed.length === 0 ? {} : { observed }) };
      }),
      // A hand-driven row is recorded only when it passed: a row that failed or
      // was not driven is left out, and the campaign is not evidence until it
      // is driven. There is no status to record but PASS.
      ...driven.map((id) => ({ id, status: "PASS", driven: true })),
    ],
    releaseMatrix: provenMatrixRows(receipt),
  };
}

const invokedAsMain = () => {
  try {
    return resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
};

/** Replace the active receipt with `body`, archiving the one it supersedes.
 *
 *  One active receipt. A campaign supersedes the one before it,
 *  and the gate would otherwise keep failing on the older document forever:
 *  its commit predates the very change the new run was recorded for. The
 *  superseded receipt is archived rather than deleted. Returns the archive
 *  path, or null when there was nothing to supersede. */
export function writeActiveReceipt(path, body) {
  const staged = `${path}.staged`;
  mkdirSync(dirname(path), { recursive: true });
  // Both branches stage first. A direct write to the active receipt can fail
  // part-way and leave a truncated document, which every later gate run then
  // fails to parse: a recording that fails must leave the evidence set as it
  // was, whether or not there was one to supersede.
  //
  // Every exit from the sequence leaves `staged` behind otherwise, and an
  // untracked file there makes the next rehearsal record a dirty tree and
  // refuse itself as evidence. The finally covers all of them: a partial
  // staged write, a failed first activation, a failed archive move, a failed
  // replacement activation, and a failed restore.
  try {
    writeFileSync(staged, body);
    if (!existsSync(path)) {
      renameSync(staged, path);
      return null;
    }
    // Every superseded receipt is archived, including one from a second
    // campaign against the same commit: it carries its own timestamp, source
    // and observations, and overwriting it would discard a campaign that ran.
    const previous = JSON.parse(readFileSync(path, "utf8"));
    const stamp = String(previous.recordedAt ?? "").replace(/[^0-9A-Za-z]/g, "").slice(0, 14) || "undated";
    const base = `release-${String(previous.runtimeCommit).slice(0, 7)}-${stamp}`;
    const archiveDir = resolve(dirname(path), "archive");
    mkdirSync(archiveDir, { recursive: true });
    // A repeated recording of the same artifact produces the same name. The
    // file already there is a campaign that ran, so the new one takes a free
    // name rather than replacing it: renameSync would delete it silently.
    let archive = resolve(archiveDir, `${base}.json`);
    for (let n = 2; existsSync(archive); n++) archive = resolve(archiveDir, `${base}-${n}.json`);
    // Move the active receipt aside only once the replacement is on disk.
    // Moving first and then failing to write would leave the repository with
    // no active receipt and a gate that refuses everything.
    renameSync(path, archive);
    try {
      renameSync(staged, path);
    } catch (error) {
      try {
        renameSync(archive, path);
      } catch (restoreError) {
        throw new Error(
          `could not activate the new receipt (${error.message}) and could not restore the previous one ` +
          `(${restoreError.message}); the previous receipt is at ${archive}`,
          { cause: error },
        );
      }
      throw error;
    }
    return archive;
  } finally {
    rmSync(staged, { force: true, recursive: true });
  }
}

/** The gate requires the receipt's commit to be an ancestor of the release
 *  commit, and a squash merge keeps no branch commit in main's history. A
 *  campaign recorded on a release branch therefore passes on the pull request
 *  head and fails on main, after the merge has thrown that commit away and the
 *  recovery is a whole new campaign. Refuse it here instead, where the fix is
 *  to check out origin/main and run again.
 *
 *  Fail closed: no reachable origin/main is a refusal, not a pass. */
/** One campaign is one checkout, unmodified. The rehearsal records the commit
 *  it ran at, but the rows a person drives run against whatever `serve.sh` is
 *  serving, and `serve.sh` serves the working tree without asking whether it is
 *  still that commit: `run.sh` checks the tree, `serve.sh` does not. So both a
 *  moved checkout and an uncommitted edit would file those rows under code they
 *  never exercised, the first under a different commit and the second under a
 *  tree the receipt calls clean. Writing evidence requires the working tree to
 *  be the commit the receipt names, with nothing on top of it. */
export function assertRecordedAtHead(commit, { cwd = ROOT } = {}) {
  const head = execFileSync("git", ["-C", cwd, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  if (head !== commit) {
    throw new Error(
      `the campaign ran at ${commit.slice(0, 7)} but the checkout is now ${head.slice(0, 7)}. ` +
      "The rows you drove ran against this checkout, not that commit. " +
      "Check that commit out again, or run the campaign again here.",
    );
  }
  // Everything except the recorder's own output. `docs/evidence/` is not an
  // evidence input, and counting it would refuse the second `--write` of one
  // campaign: the first leaves the receipt and its archived predecessor in the
  // tree, and committing them to get a clean tree moves HEAD, which the check
  // above then refuses. That left a campaign recordable exactly once.
  const modified = execFileSync(
    "git", ["-C", cwd, "status", "--porcelain", "--", ".", ":(exclude)docs/evidence"], { encoding: "utf8" },
  ).trim();
  if (modified.length > 0) {
    throw new Error(
      `the working tree has uncommitted changes, so the rows you drove ran against something ${commit.slice(0, 7)} does not contain. ` +
      "Revert them and drive the rows again, or run the whole campaign against a committed tree.",
    );
  }
  return commit;
}

export function assertReachableFrom(commit, { cwd = ROOT, ref = "origin/main" } = {}) {
  let resolved;
  try {
    resolved = execFileSync("git", ["-C", cwd, "rev-parse", "--verify", `${ref}^{commit}`], { encoding: "utf8" }).trim();
  } catch {
    throw new Error(`cannot resolve ${ref}; fetch it before recording a campaign`);
  }
  try {
    execFileSync("git", ["-C", cwd, "merge-base", "--is-ancestor", commit, resolved], { stdio: "ignore" });
  } catch {
    throw new Error(
      `the campaign ran at ${commit.slice(0, 7)}, which is not an ancestor of ${ref}. ` +
      "A squash merge keeps no branch commit, so the release would refuse this receipt after merging. " +
      `Check out ${ref} and run the campaign again.`,
    );
  }
  return commit;
}

if (invokedAsMain()) {
  const argv = process.argv.slice(2);
  const options = { receipt: undefined, write: false, source: process.env.MCP_SSO_RUN_URL, driven: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--receipt" && argv[i + 1]) options.receipt = argv[++i];
    else if (argv[i] === "--write") options.write = true;
    else if (argv[i] === "--row" && argv[i + 1]) options.driven.push(argv[++i]);
    else throw new Error("usage: record-receipt.mjs --receipt <file> [--row <id>]... [--write]");
  }
  if (!options.receipt) throw new Error("--receipt is required");
  const receipt = assertClientVersions(readRehearsalReceipt(JSON.parse(readFileSync(options.receipt, "utf8"))));
  // Only when the document is being written: printing one for inspection asks
  // nothing of the repository. Both guards, because a campaign has to be one
  // commit and that commit has to survive the merge.
  if (options.write) {
    assertRecordedAtHead(receipt.runtimeCommit);
    assertReachableFrom(receipt.runtimeCommit);
  }
  const evidence = toEvidence(receipt, { source: options.source, driven: options.driven });
  const body = `${JSON.stringify(evidence, null, 2)}\n`;
  if (options.write) {
    const path = resolve(ROOT, "docs/evidence/release.json");
    const archived = writeActiveReceipt(path, body);
    if (archived) process.stdout.write(`${archived} archived\n`);
    process.stdout.write(`${path} written for ${receipt.runtimeCommit}\n`);
    // The page a person reads is not generated, and it should not silently
    // fall behind the receipt either. This is what changed, in the words the
    // page uses, for whoever lands the evidence.
    process.stdout.write(`\nFor docs/client-compatibility.md, at runtime commit ${receipt.runtimeCommit.slice(0, 7)}:\n`);
    for (const row of evidence.rows) {
      const observed = row.observed?.length > 0 ? `  (${row.observed.join("; ")})` : "";
      process.stdout.write(`  ${row.id}${observed}\n`);
    }
  } else {
    process.stdout.write(body);
  }
}
