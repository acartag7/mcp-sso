// The release-readiness gate (§15). Evidence is data: one JSON receipt per
// campaign under docs/evidence/. This reads receipts, package.json, the release
// matrix, and the published-release row, and refuses a release whose evidence
// does not match what ships. It parses no prose. docs/client-compatibility.md
// is written for readers, and nothing here reads it.
import { changedEvidenceInputs, isAncestor, resolveCommit } from "./release-evidence-git.mjs";

const SHA = /^[0-9a-f]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const ROW_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/;
const PRODUCERS = new Set(["rehearsal", "operator"]);
const STATUS_LINE = /^\|\s*npm package and tag\s*\|\s*`mcp-sso@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`\s+and\s+`v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`\s*\|$/m;

/** The version the published-release row claims, or undefined. One row, one
 *  grammar; the pair must agree with itself before it can agree with the
 *  package. */
function claimedVersion(status, errors) {
  const matches = [...String(status ?? "").matchAll(new RegExp(STATUS_LINE.source, "gm"))];
  if (matches.length !== 1) {
    errors.push(`status version: expected one npm package and tag row, found ${matches.length}`);
    return undefined;
  }
  const [, npmVersion, tagVersion] = matches[0];
  if (npmVersion !== tagVersion) {
    errors.push(`status version mismatch: npm claims ${npmVersion}, tag claims ${tagVersion}`);
    return undefined;
  }
  return npmVersion;
}

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
  }
  return receipt;
}

/** The release matrix as a mapping from export name to the rows that resolve it
 *  from the packed artifact, rejecting a malformed row on the way. */
function parseReleaseRows(releaseMatrix, errors) {
  const rows = Array.isArray(releaseMatrix?.rows) ? releaseMatrix.rows : undefined;
  if (rows === undefined) {
    errors.push("release matrix: rows must be an array");
    return new Map();
  }
  const byExport = new Map();
  const ids = new Set();
  for (const row of rows) {
    const id = String(row?.id);
    if (!ROW_ID.test(id)) { errors.push("release matrix: a row has no readable id"); continue; }
    if (ids.has(id)) { errors.push(`release matrix: duplicate row ${id}`); continue; }
    ids.add(id);
    if (typeof row.title !== "string" || row.title.trim() === "") errors.push(`release matrix: ${id} requires a non-empty title`);
    const evidence = Array.isArray(row.evidence) ? row.evidence : [];
    if (evidence.length === 0 || evidence.some((item) => typeof item?.file !== "string" || typeof item?.name !== "string")) {
      errors.push(`release matrix: ${id} requires executable evidence with file and name`);
    }
    const exports = row.exports;
    if (exports === undefined) continue;
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
  return byExport;
}

/**
 * @param receipts `{ [label]: receipt }`, one entry per file under docs/evidence/.
 */
export function evaluateReleaseReadiness({ packageJson, releaseMatrix, receipts, status, gitCwd, releaseCommit = "HEAD" }) {
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

  const claimed = claimedVersion(status, errors);
  if (claimed !== undefined && packageVersion !== undefined && claimed !== packageVersion) {
    errors.push(`version mismatch: package.json is ${packageVersion}, docs/verification-status.md claims ${claimed}`);
  }

  const entries = Object.entries(receipts ?? {});
  if (entries.length === 0) errors.push("no evidence receipt found under docs/evidence/");
  const valid = [];
  for (const [label, value] of entries) {
    const receipt = readReceipt(value, label, errors);
    if (receipt !== undefined) valid.push({ label, receipt });
  }

  const resolvedRelease = resolveCommit(gitCwd, releaseCommit);
  if (!resolvedRelease) errors.push(`release commit is not available in git history: ${releaseCommit}`);

  // Every export needs one passing packed-artifact row, from any receipt that
  // carried a release-matrix result.
  const byExport = parseReleaseRows(releaseMatrix, errors);
  const provenRows = new Set(valid.flatMap(({ receipt }) => receipt.releaseMatrix ?? []));
  for (const name of publicExports) {
    const covering = (byExport.get(name) ?? []).filter((id) => provenRows.has(id));
    if (covering.length === 0) errors.push(`no live evidence covers export ${name}`);
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
    const changedInputs = changedEvidenceInputs(gitCwd, resolvedRuntime, resolvedRelease);
    if (changedInputs.length > 0) staleEvidence.push({ label, commit: receipt.runtimeCommit, changedInputs });
  }

  return { errors, staleEvidence, releaseCommit: resolvedRelease, exportCount: publicExports.length, version: packageVersion };
}
