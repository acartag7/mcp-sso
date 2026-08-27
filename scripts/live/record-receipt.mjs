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
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
  if (receipt.dirty === true) throw new Error("the receipt was produced from a dirty tree");
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
  const receipt = readRehearsalReceipt(JSON.parse(readFileSync(options.receipt, "utf8")));
  if (options.requireHead) {
    const head = execFileSync("git", ["-C", ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    if (head !== receipt.runtimeCommit) throw new Error("the receipt's runtime commit is not the checked-out HEAD");
  }
  const evidence = toEvidence(receipt, { source: options.source });
  const body = `${JSON.stringify(evidence, null, 2)}\n`;
  if (options.write) {
    const path = resolve(ROOT, `docs/evidence/rehearsal-${receipt.runtimeCommit.slice(0, 7)}.json`);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, body);
    process.stdout.write(`${path} written for ${receipt.runtimeCommit}\n`);
  } else {
    process.stdout.write(body);
  }
}
