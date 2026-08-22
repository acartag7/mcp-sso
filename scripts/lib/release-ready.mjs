import { execFileSync } from "node:child_process";

const SHA = /^[0-9a-f]{7,40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const EXPORT_HEADING = "## Public export live evidence";
const EXPORT_TABLE_HEADER = "| Export | Live evidence | Runtime commit |";
const EXPORT_TABLE_DIVIDER = "| --- | --- | --- |";
const STATUS_HEADING = "## Published release";
const STATUS_TABLE_HEADER = "| Item | Status |";
const STATUS_TABLE_DIVIDER = "| --- | --- |";

function sectionAfter(source, heading) {
  const start = source.indexOf(`${heading}\n`);
  if (start === -1) return undefined;
  const bodyStart = start + heading.length + 1;
  const nextHeading = source.indexOf("\n## ", bodyStart);
  return source.slice(bodyStart, nextHeading === -1 ? undefined : nextHeading);
}

function gitOutput(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function resolveCommit(cwd, value) {
  try {
    return gitOutput(cwd, ["rev-parse", "--verify", `${value}^{commit}`]);
  } catch {
    return undefined;
  }
}

function isAncestor(cwd, ancestor, descendant) {
  try {
    execFileSync("git", ["merge-base", "--is-ancestor", ancestor, descendant], {
      cwd,
      stdio: "ignore",
    });
    return true;
  } catch (error) {
    if (error && typeof error === "object" && "status" in error && error.status === 1) return false;
    throw error;
  }
}

function renderedTableRows(source, heading, header, divider, label, errors) {
  const section = sectionAfter(source, heading);
  if (section === undefined) {
    errors.push(`${label}: missing ${heading} section`);
    return [];
  }
  const lines = section.split("\n");
  if (section.includes("<!--") || section.includes("-->")) {
    errors.push(`${label}: HTML comments are not allowed in the table section`);
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
  for (let index = 0; index < lines.length; index += 1) {
    if (index >= tableStart && index < tableEnd) continue;
    if (lines[index].trimStart().startsWith("|")) {
      errors.push(`${label}: table-shaped row outside the rendered table`);
    }
  }
  return lines.slice(tableStart + 2, tableEnd);
}

function parseStatusVersion(source, errors) {
  const tableRows = renderedTableRows(source, STATUS_HEADING, STATUS_TABLE_HEADER, STATUS_TABLE_DIVIDER, "status version", errors);
  const rows = tableRows.flatMap((line) => {
    const match = line.match(/^\| npm package and tag \| `mcp-sso@([^`]+)` and `v([^`]+)` \|$/);
    return match ? [match] : [];
  });
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

function parseReleaseIds(releaseMatrix, errors) {
  if (!releaseMatrix || typeof releaseMatrix !== "object" || Array.isArray(releaseMatrix) || !Array.isArray(releaseMatrix.rows)) {
    errors.push("release matrix: expected an object with a rows array");
    return new Set();
  }
  const ids = new Set();
  for (const row of releaseMatrix.rows) {
    if (!row || typeof row !== "object" || Array.isArray(row) || typeof row.id !== "string" || !/^RM\.\d+$/.test(row.id)) {
      errors.push("release matrix: every row requires an RM.N id");
      continue;
    }
    if (ids.has(row.id)) errors.push(`release matrix: duplicate row ${row.id}`);
    ids.add(row.id);
  }
  return ids;
}

function recordedRuntimeCommits(source) {
  return [...source.matchAll(/Runtime commit `([^`]+)`(?:, later merged without runtime changes as `([^`]+)`)?/g)]
    .map((match) => match[2] ?? match[1]);
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
  const releaseIds = parseReleaseIds(releaseMatrix, errors);
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
      if (!releaseIds.has(evidenceId)) errors.push(`unknown live evidence ID ${evidenceId} for export ${exportName}`);
    }
  }

  const resolvedRelease = resolveCommit(gitCwd, releaseCommit);
  if (!resolvedRelease) errors.push(`release commit is not available in git history: ${releaseCommit}`);
  const commits = new Set([...recordedRuntimeCommits(compatibility), ...[...evidenceRows.values()].map((row) => row.commit)]);
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
    }
  }
  return { errors, releaseCommit: resolvedRelease, exportCount: publicExports.length, version: packageVersion };
}
