import { changedEvidenceInputs, evidenceInputDigest, isAncestor, resolveCommit } from "./release-evidence-git.mjs";
import { parseProviderRuntimeCommits } from "./release-provider-evidence.mjs";

const SHA = /^[0-9a-f]{7,40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const EXPORT_HEADING = "## Public export live evidence";
const EXPORT_TABLE_HEADER = "| Export | Live evidence | Runtime commit |";
const EXPORT_TABLE_DIVIDER = "| --- | --- | --- |";
const PROVIDER_HEADING = "## Current matrix";
const PROVIDER_TABLE_HEADER = "| Provider | Client | Flow driven | Status | Date | Limits |";
const PROVIDER_TABLE_DIVIDER = "| --- | --- | --- | --- | --- | --- |";
const STATUS_HEADING = "## Published release";
const STATUS_TABLE_HEADER = "| Item | Status |";
const STATUS_TABLE_DIVIDER = "| --- | --- |";
const STATUS_VERSION_ITEM = "npm package and tag";
const HTML_ENTITY = /&(?:#[0-9]+|#x[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);/;
const CANONICAL_H2 = /^## [A-Za-z0-9](?:[A-Za-z0-9 .-]*[A-Za-z0-9])?$/;

function hasNoncanonicalHeading(lines) {
  const renderedLines = lines.map((line) => line.replace(/^\s*(?:>\s*)+/, ""));
  return renderedLines.some((line, index) => {
    if (/^[ ]{0,3}##(?:[ \t]+|$)/.test(line) && !CANONICAL_H2.test(lines[index])) return true;
    if (/<\/?h2\b/i.test(line)) return true;
    return /^[ ]{0,3}-+[ \t]*$/.test(line) && index > 0 && renderedLines[index - 1].trim() !== "";
  });
}

function hasNoncanonicalTableMarkup(line) {
  let outsideCode = "";
  let cursor = 0;
  for (const match of line.matchAll(/`([^`\r\n]+)`/g)) {
    const start = match.index;
    const end = start + match[0].length;
    if (/^[\p{L}\p{N}]$/u.test(line[start - 1] ?? "") || /^[\p{L}\p{N}]$/u.test(line[end] ?? "")) return true;
    outsideCode += line.slice(cursor, start);
    cursor = end;
  }
  outsideCode += line.slice(cursor);
  return HTML_ENTITY.test(line) || /[`\\*_~[\]<>]/.test(outsideCode);
}

function uniqueSectionAfter(source, heading, label, errors) {
  const lines = source.split("\n");
  const title = heading.slice(3).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const headingPattern = new RegExp(`^##[ \\t]+${title}(?:[ \\t]+#+)?[ \\t]*$`);
  const renderedHeadings = lines.flatMap((line, index) => {
    const unquoted = line.replace(/^\s*(?:>\s*)+/, "");
    return headingPattern.test(unquoted) ? [index] : [];
  });
  const starts = lines.flatMap((line, index) => line === heading ? [index] : []);
  if (hasNoncanonicalHeading(lines)) {
    errors.push(`${label}: evidence documents require canonical level-two headings`);
    return undefined;
  }
  if (starts.length !== 1 || renderedHeadings.length !== 1) {
    errors.push(`${label}: expected one canonical ${heading} section, found ${renderedHeadings.length}`);
    return undefined;
  }
  let end = starts[0] + 1;
  while (end < lines.length && !/^##[ \t]+/.test(lines[end])) end += 1;
  return lines.slice(starts[0] + 1, end).join("\n");
}


function renderedTableRows(source, heading, header, divider, label, errors) {
  const section = uniqueSectionAfter(source, heading, label, errors);
  if (section === undefined) return [];
  const lines = section.split("\n");
  if (section.includes("<!--") || section.includes("-->")) {
    errors.push(`${label}: HTML comments are not allowed in the table section`);
  }
  if (/[<>]/.test(section.replace(/`[^`\r\n]*`/g, ""))) {
    errors.push(`${label}: raw angle-bracket markup is not allowed in the table section`);
  }
  if (lines.some((line) => /^\s*(?:`{3,}|~{3,})/.test(line))) {
    errors.push(`${label}: fenced blocks are not allowed in the table section`);
  }
  const tableStarts = lines.flatMap((line, index) => line === header ? [index] : []);
  if (tableStarts.length !== 1) {
    errors.push(`${label}: expected one rendered table, found ${tableStarts.length}`);
    return [];
  }
  const tableStart = tableStarts[0];
  if (lines[tableStart + 1] !== divider) {
    errors.push(`${label}: rendered table has a malformed divider`);
    return [];
  }
  let tableEnd = tableStart + 2;
  while (tableEnd < lines.length && lines[tableEnd].startsWith("|")) tableEnd += 1;
  if (lines.slice(tableStart + 2, tableEnd).some(hasNoncanonicalTableMarkup)) {
    errors.push(`${label}: table rows contain noncanonical Markdown`);
  }
  for (let index = 0; index < lines.length; index += 1) {
    if (index >= tableStart && index < tableEnd) continue;
    const unquoted = lines[index].replace(/^\s*(?:>\s*)+/, "");
    if (unquoted.trimStart().startsWith("|")) {
      errors.push(`${label}: table-shaped row outside the rendered table`);
    }
  }
  return lines.slice(tableStart + 2, tableEnd);
}

function parseStatusVersion(source, errors) {
  const tableRows = renderedTableRows(source, STATUS_HEADING, STATUS_TABLE_HEADER, STATUS_TABLE_DIVIDER, "status version", errors);
  const rows = [];
  for (const line of tableRows) {
    const rawCells = line.split("|").slice(1, -1);
    if (rawCells.length !== 2) {
      errors.push("status version: malformed table row");
      continue;
    }
    const rawFirstCell = rawCells[0];
    const firstCell = rawFirstCell?.trim();
    if (!firstCell || rawFirstCell !== ` ${firstCell} ` || !/^[A-Za-z0-9]+(?: [A-Za-z0-9]+)*$/.test(firstCell)) {
      errors.push("status version: malformed item label");
      continue;
    }
    if (firstCell.toLowerCase() === STATUS_VERSION_ITEM && firstCell !== STATUS_VERSION_ITEM) {
      errors.push("status version: malformed npm package and tag row");
      continue;
    }
    if (firstCell !== STATUS_VERSION_ITEM) continue;
    const match = line.match(/^\| npm package and tag \| `mcp-sso@([^`]+)` and `v([^`]+)` \|$/);
    if (!match) {
      errors.push("status version: malformed npm package and tag row");
      continue;
    }
    rows.push(match);
  }
  if (rows.length !== 1) {
    errors.push(`status version: expected one npm package and tag row, found ${rows.length}`);
    return undefined;
  }
  const packageVersion = rows[0][1];
  const tagVersion = rows[0][2];
  if (packageVersion !== tagVersion) {
    errors.push(`status version mismatch: npm claims ${packageVersion}, tag claims ${tagVersion}`);
    return undefined;
  }
  if (!VERSION.test(packageVersion)) {
    errors.push(`status version is malformed: ${packageVersion}`);
    return undefined;
  }
  return packageVersion;
}

function parseExportEvidence(source, errors) {
  const rows = new Map();
  const tableRows = renderedTableRows(source, EXPORT_HEADING, EXPORT_TABLE_HEADER, EXPORT_TABLE_DIVIDER, "export evidence", errors);
  for (const line of tableRows) {
    const match = line.match(/^\| `([^`]+)` \| ([^|]+) \| `([^`]+)` \|$/);
    if (!match) {
      const namedExport = line.match(/^\| `([^`]+)` \|/)?.[1];
      errors.push(namedExport
        ? `export evidence: malformed table row for ${namedExport}`
        : "export evidence: malformed table row");
      continue;
    }
    const [, exportName, evidence, commit] = match;
    if (rows.has(exportName)) {
      errors.push(`export evidence: duplicate row for ${exportName}`);
      continue;
    }
    if (!/^`RM\.\d+`(?:, `RM\.\d+`)*$/.test(evidence.trim())) {
      errors.push(`export evidence: ${exportName} has malformed live evidence ${evidence.trim()}`);
    }
    if (!/^[0-9a-f]{40}$/.test(commit)) {
      errors.push(`export evidence: ${exportName} has invalid runtime commit ${commit}`);
    }
    const evidenceIds = [...evidence.matchAll(/`(RM\.\d+)`/g)].map((idMatch) => idMatch[1]);
    rows.set(exportName, { commit, evidenceIds });
  }
  return rows;
}

function parseReleaseRows(releaseMatrix, errors) {
  if (!releaseMatrix || typeof releaseMatrix !== "object" || Array.isArray(releaseMatrix) || !Array.isArray(releaseMatrix.rows)) {
    errors.push("release matrix: expected an object with a rows array");
    return new Map();
  }
  const rows = new Map();
  for (const row of releaseMatrix.rows) {
    if (!row || typeof row !== "object" || Array.isArray(row) || typeof row.id !== "string" || !/^RM\.\d+$/.test(row.id)) {
      errors.push("release matrix: every row requires an RM.N id");
      continue;
    }
    if (rows.has(row.id)) errors.push(`release matrix: duplicate row ${row.id}`);
    let executable = true;
    if (typeof row.title !== "string" || row.title.trim() !== row.title || row.title.length === 0) {
      errors.push(`release matrix: ${row.id} requires a non-empty title`);
      executable = false;
    }
    if (!Array.isArray(row.evidence) || row.evidence.length === 0
      || row.evidence.some((item) => !item || typeof item !== "object" || Array.isArray(item)
        || typeof item.file !== "string" || item.file.trim() !== item.file || item.file.length === 0
        || typeof item.name !== "string" || item.name.trim() !== item.name || item.name.length === 0)) {
      errors.push(`release matrix: ${row.id} requires executable evidence with file and name`);
      executable = false;
    }
    if (!Array.isArray(row.exports) || row.exports.some((name) => typeof name !== "string")) {
      errors.push(`release matrix: ${row.id} requires an exports array of strings`);
      rows.set(row.id, new Set());
      continue;
    }
    const coveredExports = new Set(row.exports);
    if (coveredExports.size !== row.exports.length) errors.push(`release matrix: ${row.id} has duplicate exports`);
    if (row.exports.length > 0 && row.packedArtifact !== true) {
      errors.push(`release matrix: ${row.id} requires packedArtifact true before its exports can count`);
      executable = false;
    }
    rows.set(row.id, executable ? coveredExports : new Set());
  }
  return rows;
}

export function evaluateReleaseReadiness({ packageJson, releaseMatrix, compatibility, status, gitCwd, releaseCommit = "HEAD" }) {
  const errors = [];
  const packageVersion = packageJson?.version;
  const exportsValue = packageJson?.exports;
  if (typeof packageVersion !== "string" || !VERSION.test(packageVersion)) {
    errors.push(`package version is malformed: ${String(packageVersion)}`);
  }
  if (!exportsValue || typeof exportsValue !== "object" || Array.isArray(exportsValue)) {
    errors.push("package exports: expected an object");
  }

  const statusVersion = parseStatusVersion(status, errors);
  if (typeof packageVersion === "string" && statusVersion && packageVersion !== statusVersion) {
    errors.push(`version mismatch: package.json is ${packageVersion}, docs/verification-status.md is ${statusVersion}`);
  }

  const evidenceRows = parseExportEvidence(compatibility, errors);
  const releaseRows = parseReleaseRows(releaseMatrix, errors);
  const publicExports = exportsValue && typeof exportsValue === "object" && !Array.isArray(exportsValue)
    ? Object.keys(exportsValue)
    : [];
  for (const exportName of publicExports) {
    if (!evidenceRows.has(exportName)) errors.push(`missing live evidence row for export ${exportName}`);
  }
  for (const exportName of evidenceRows.keys()) {
    if (!publicExports.includes(exportName)) errors.push(`live evidence row names unknown export ${exportName}`);
  }
  for (const [exportName, row] of evidenceRows) {
    for (const evidenceId of row.evidenceIds) {
      const coveredExports = releaseRows.get(evidenceId);
      if (!coveredExports) errors.push(`unknown live evidence ID ${evidenceId} for export ${exportName}`);
      else if (!coveredExports.has(exportName)) errors.push(`live evidence ID ${evidenceId} does not cover export ${exportName}`);
    }
  }
  for (const [evidenceId, coveredExports] of releaseRows) {
    for (const exportName of coveredExports) {
      if (!publicExports.includes(exportName)) errors.push(`release matrix row ${evidenceId} names unknown export ${exportName}`);
    }
  }

  const resolvedRelease = resolveCommit(gitCwd, releaseCommit);
  if (!resolvedRelease) errors.push(`release commit is not available in git history: ${releaseCommit}`);
  const providerCommits = [];
  const providerRows = renderedTableRows(
    compatibility, PROVIDER_HEADING, PROVIDER_TABLE_HEADER, PROVIDER_TABLE_DIVIDER, "provider evidence", errors,
  );
  for (const receipt of parseProviderRuntimeCommits(providerRows, errors)) {
    if (receipt.evidenceDigest) {
      const resolvedMerge = resolveCommit(gitCwd, receipt.mergeCommit);
      if (!resolvedMerge) {
        errors.push(`provider evidence: ${receipt.provider} / ${receipt.client} merge commit is unavailable: ${receipt.mergeCommit}`);
        continue;
      }
      const actualDigest = evidenceInputDigest(gitCwd, resolvedMerge);
      if (actualDigest !== receipt.evidenceDigest) {
        errors.push(
          `provider evidence: ${receipt.provider} / ${receipt.client} evidence digest does not match merge commit ${receipt.mergeCommit}`,
        );
        continue;
      }
      providerCommits.push(resolvedMerge);
      continue;
    }
    const resolvedRuntime = resolveCommit(gitCwd, receipt.runtimeCommit);
    if (!resolvedRuntime) {
      errors.push(`provider evidence: ${receipt.provider} / ${receipt.client} runtime commit is unavailable: ${receipt.runtimeCommit}`);
      continue;
    }
    providerCommits.push(resolvedRuntime);
  }
  const commits = new Set([...providerCommits, ...[...evidenceRows.values()].map((row) => row.commit)]);
  for (const commit of commits) {
    if (!SHA.test(commit)) {
      errors.push(`recorded runtime commit is malformed: ${commit}`);
      continue;
    }
    const resolvedRuntime = resolveCommit(gitCwd, commit);
    if (!resolvedRuntime) {
      errors.push(`recorded runtime commit is not available in git history: ${commit}`);
      continue;
    }
    if (resolvedRelease && !isAncestor(gitCwd, resolvedRuntime, resolvedRelease)) {
      errors.push(`recorded runtime commit ${commit} is not an ancestor of release commit ${resolvedRelease}`);
      continue;
    }
    if (resolvedRelease) {
      const changedInputs = changedEvidenceInputs(gitCwd, resolvedRuntime, resolvedRelease);
      if (changedInputs.length > 0) {
        errors.push(`recorded runtime commit ${commit} predates release runtime changes: ${changedInputs.join(", ")}`);
      }
    }
  }
  return { errors, releaseCommit: resolvedRelease, exportCount: publicExports.length, version: packageVersion };
}
