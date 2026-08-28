// The release-readiness gate (§15). Evidence is data: one JSON receipt per
// campaign under docs/evidence/. This reads receipts, package.json, the release
// matrix, and the published-release row, and refuses a release whose evidence
// does not match what ships. It parses no prose. docs/client-compatibility.md
// is written for readers, and nothing here reads it.
import { ROWS } from "../live/rehearsal-support.mjs";
import { changedEvidenceInputs, isAncestor, resolveCommit } from "./release-evidence-git.mjs";

const SHA = /^[0-9a-f]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const ROW_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/;
const MATRIX_ROW_ID = /^RM\.\d+$/;
const PRODUCERS = new Set(["rehearsal", "operator"]);
/** The active receipt each producer writes. Anything else in the directory is
 *  a document nobody records to, and a superseded one belongs in archive/. */
export const ACTIVE_RECEIPTS = Object.freeze({ rehearsal: "rehearsal.json", operator: "operator.json" });
/** One receipt, validated as data. A receipt that claims rows it did not
 *  complete is not evidence, and says so itself rather than leaving a reader
 *  to infer it from row statuses. */
function readReceipt(receipt, label, errors) {
  const fail = (message) => { errors.push(`${label}: ${message}`); return undefined; };
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) return fail("is not an object");
  if (receipt.schema !== 1) return fail(`unrecognised schema ${JSON.stringify(receipt.schema)}`);
  if (!PRODUCERS.has(receipt.producer)) return fail(`unknown producer ${JSON.stringify(receipt.producer)}`);
  if (typeof receipt.runtimeCommit !== "string" || !SHA.test(receipt.runtimeCommit)) {
    return fail(`runtime commit is malformed: ${String(receipt.runtimeCommit)}`);
  }
  if (receipt.complete !== true) return fail("is partial, so it is not evidence");
  // `complete` is the producer's summary of itself. For a rehearsal it is
  // re-derived here, because the gate reads a committed file rather than the
  // run that wrote it: a receipt truncated to its release-matrix row would
  // otherwise cover every export while the identity and client evidence was
  // gone.
  if (receipt.producer === "rehearsal") {
    const expected = new Set(ROWS.map((row) => row.id));
    const ids = new Set((Array.isArray(receipt.rows) ? receipt.rows : []).map((row) => row?.id));
    const missing = [...expected].filter((id) => !ids.has(id));
    if (missing.length > 0) return fail(`claims to be complete without ${missing.length} row(s) the rehearsal runs`);
    // Exact, not merely sufficient: a row the rehearsal does not define proves
    // nothing, and a receipt carrying one is not the run it says it is.
    const invented = [...ids].filter((id) => !expected.has(id));
    if (invented.length > 0) return fail(`records ${invented.length} row(s) the rehearsal does not define: ${invented.slice(0, 3).join(", ")}`);
  }
  if (!Array.isArray(receipt.rows) || receipt.rows.length === 0) return fail("records no rows");
  const seen = new Set();
  for (const row of receipt.rows) {
    if (!row || typeof row !== "object" || !ROW_ID.test(String(row.id))) return fail("has a row with no readable id");
    if (seen.has(row.id)) return fail(`repeats row ${row.id}`);
    seen.add(row.id);
    if (row.status !== "PASS") return fail(`row ${row.id} did not pass (${String(row.status)})`);
  }
  const matrix = receipt.releaseMatrix;
  if (matrix !== undefined) {
    if (!Array.isArray(matrix) || matrix.some((id) => !ROW_ID.test(String(id)))) {
      return fail("names release-matrix rows that are not readable ids");
    }
    // Export coverage comes from the release matrix, which only the rehearsal
    // runs. An operator drives real clients against a served leg and proves
    // nothing about a packed artifact, so a receipt of theirs claiming matrix
    // rows is claiming someone else's work.
    if (receipt.producer !== "rehearsal") return fail("is not a rehearsal receipt, so it cannot carry release-matrix rows");
    if (matrix.length > 0 && !receipt.rows.some((row) => row.id === "release-matrix" && row.status === "PASS")) {
      return fail("names release-matrix rows without a passing release-matrix row");
    }
  }
  return receipt;
}

/** The release matrix as a mapping from export name to the rows that resolve it
 *  from the packed artifact, rejecting a malformed row on the way. */
function parseReleaseRows(releaseMatrix, errors) {
  if (!releaseMatrix || typeof releaseMatrix !== "object" || Array.isArray(releaseMatrix)) {
    errors.push("release matrix: expected an object with a rows array");
    return { byExport: new Map(), knownRows: new Set() };
  }
  const rows = Array.isArray(releaseMatrix.rows) ? releaseMatrix.rows : undefined;
  if (rows === undefined) {
    errors.push("release matrix: expected an object with a rows array");
    return { byExport: new Map(), knownRows: new Set() };
  }
  const byExport = new Map();
  const ids = new Set();
  for (const row of rows) {
    const id = typeof row?.id === "string" ? row.id : "";
    if (!MATRIX_ROW_ID.test(id)) { errors.push("release matrix: every row requires an RM.N id"); continue; }
    if (ids.has(id)) { errors.push(`release matrix: duplicate row ${id}`); continue; }
    ids.add(id);
    if (typeof row.title !== "string" || row.title.trim() !== row.title || row.title === "") errors.push(`release matrix: ${id} requires a non-empty title`);
    const evidence = Array.isArray(row.evidence) ? row.evidence : [];
    const trimmed = (value) => typeof value === "string" && value.trim() === value && value !== "";
    if (evidence.length === 0 || evidence.some((item) => !trimmed(item?.file) || !trimmed(item?.name))) {
      errors.push(`release matrix: ${id} requires executable evidence with file and name`);
    }
    // Every row declares the exports it resolves, even when that is none: an
    // absent array is a row that never said, which the old gate refused too.
    const exports = row.exports;
    if (!Array.isArray(exports) || exports.some((name) => typeof name !== "string")) {
      errors.push(`release matrix: ${id} requires an exports array of strings`);
      continue;
    }
    if (new Set(exports).size !== exports.length) errors.push(`release matrix: ${id} has duplicate exports`);
    if (exports.length > 0 && row.packedArtifact !== true) {
      errors.push(`release matrix: ${id} requires packedArtifact true before its exports count`);
      continue;
    }
    for (const name of exports) byExport.set(name, [...(byExport.get(name) ?? []), id]);
  }
  return { byExport, knownRows: ids };
}

/**
 * @param receipts `{ [label]: receipt }`, one entry per file under docs/evidence/.
 */
export function evaluateReleaseReadiness({ packageJson, releaseMatrix, receipts, gitCwd, releaseCommit = "HEAD" }) {
  const errors = [];
  const staleEvidence = [];
  const packageVersion = packageJson?.version;
  if (typeof packageVersion !== "string" || !VERSION.test(packageVersion)) {
    errors.push(`package version is malformed: ${String(packageVersion)}`);
  }
  const exportsValue = packageJson?.exports;
  if (!exportsValue || typeof exportsValue !== "object" || Array.isArray(exportsValue)) {
    errors.push("package exports must be an object");
  }
  const publicExports = exportsValue && typeof exportsValue === "object" && !Array.isArray(exportsValue)
    ? Object.keys(exportsValue) : [];

  // One active receipt per producer, under the name that says which. A missing
  // operator receipt would otherwise pass on the rehearsal alone, publishing
  // without the campaign a person drove.
  const entries = Object.entries(receipts ?? {});
  const valid = [];
  for (const [producer, label] of Object.entries(ACTIVE_RECEIPTS)) {
    if (!Object.hasOwn(receipts ?? {}, label)) { errors.push(`no ${producer} receipt at docs/evidence/${label}`); continue; }
    const receipt = readReceipt(receipts[label], label, errors);
    if (receipt === undefined) continue;
    if (receipt.producer !== producer) { errors.push(`${label}: holds a ${receipt.producer} receipt`); continue; }
    valid.push({ label, receipt });
  }
  for (const [label] of entries) {
    if (!Object.values(ACTIVE_RECEIPTS).includes(label)) errors.push(`docs/evidence/${label} is not an active receipt; a superseded one belongs in archive/`);
  }

  const resolvedRelease = resolveCommit(gitCwd, releaseCommit);
  if (!resolvedRelease) errors.push(`release commit is not available in git history: ${releaseCommit}`);

  // Every export needs one passing packed-artifact row, from any receipt that
  // carried a release-matrix result.
  const { byExport, knownRows } = parseReleaseRows(releaseMatrix, errors);
  const provenRows = new Set();
  for (const { label, receipt } of valid) {
    for (const id of receipt.releaseMatrix ?? []) {
      // A receipt names rows the matrix defines. An id it invents proves
      // nothing, and silently counting it would let a receipt cover an export
      // no executable row ever resolved.
      if (!knownRows.has(id)) { errors.push(`${label}: names ${id}, which the release matrix does not define`); continue; }
      provenRows.add(id);
    }
  }
  for (const name of publicExports) {
    const covering = (byExport.get(name) ?? []).filter((id) => provenRows.has(id));
    if (covering.length === 0) errors.push(`no live evidence covers export ${name}`);
  }
  // A row claiming an export the package no longer declares is a mapping left
  // behind, and it would keep looking like coverage of something.
  for (const [name, rows] of byExport) {
    if (!publicExports.includes(name)) errors.push(`release matrix: ${rows.join(", ")} names export ${name}, which the package does not declare`);
  }
  for (const { label, receipt } of valid) {
    const resolvedRuntime = resolveCommit(gitCwd, receipt.runtimeCommit);
    if (!resolvedRuntime) {
      errors.push(`${label}: runtime commit is not available in git history: ${receipt.runtimeCommit}`);
      continue;
    }
    if (!resolvedRelease) continue;
    if (!isAncestor(gitCwd, resolvedRuntime, resolvedRelease)) {
      errors.push(`${label}: runtime commit ${receipt.runtimeCommit.slice(0, 7)} is not an ancestor of the release commit`);
      continue;
    }
    const changedInputs = changedEvidenceInputs(gitCwd, resolvedRuntime, resolvedRelease, { producer: receipt.producer });
    if (changedInputs.length > 0) staleEvidence.push({ label, commit: receipt.runtimeCommit, changedInputs });
  }

  return { errors, staleEvidence, releaseCommit: resolvedRelease, exportCount: publicExports.length, version: packageVersion };
}
