// Turn a passing rehearsal receipt into the release evidence the gate reads
// (§15): one JSON document under docs/evidence/, naming the commit the campaign
// ran against and what it observed.
//
//   node scripts/live/record-receipt.mjs --receipt <receipt.json> [--write] [--require-head]
//
// Without --write the document goes to stdout. A receipt that is not evidence,
// a partial run, a dirty tree, or a failed row, is refused: the rehearsal
// already decided that, and this never second-guesses it into a pass.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ROWS } from "./rehearsal-support.mjs";

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

/** The evidence document, in the schema the gate reads. */
export function toEvidence(receipt, { source } = {}) {
  return {
    schema: 1,
    producer: "rehearsal",
    runtimeCommit: receipt.runtimeCommit,
    recordedAt: receipt.finishedAt ?? receipt.startedAt,
    ...(source === undefined ? {} : { source }),
    complete: true,
    rows: receipt.rows.map((row) => {
      const observed = observationsOf(row);
      return { id: row.id, status: row.status, ...(observed.length === 0 ? {} : { observed }) };
    }),
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
 *  One active receipt per producer. A campaign supersedes the one before it,
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
    const base = `rehearsal-${String(previous.runtimeCommit).slice(0, 7)}-${stamp}`;
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

if (invokedAsMain()) {
  const argv = process.argv.slice(2);
  const options = { receipt: undefined, write: false, requireHead: false, source: process.env.MCP_SSO_RUN_URL };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--receipt" && argv[i + 1]) options.receipt = argv[++i];
    else if (argv[i] === "--write") options.write = true;
    else if (argv[i] === "--require-head") options.requireHead = true;
    else throw new Error("usage: record-receipt.mjs --receipt <file> [--write] [--require-head]");
  }
  if (!options.receipt) throw new Error("--receipt is required");
  const receipt = assertClientVersions(readRehearsalReceipt(JSON.parse(readFileSync(options.receipt, "utf8"))));
  if (options.requireHead) {
    const head = execFileSync("git", ["-C", ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    if (head !== receipt.runtimeCommit) throw new Error("the receipt's runtime commit is not the checked-out HEAD");
  }
  const evidence = toEvidence(receipt, { source: options.source });
  const body = `${JSON.stringify(evidence, null, 2)}\n`;
  if (options.write) {
    const path = resolve(ROOT, "docs/evidence/rehearsal.json");
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
