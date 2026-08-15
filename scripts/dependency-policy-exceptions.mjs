import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const RECORD_KEYS = new Set([
  "kind",
  "package",
  "advisoryIds",
  "adoptedVersion",
  "adoptedAt",
  "justification",
]);

function validPackageName(value) {
  return typeof value === "string"
    && /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(value);
}

function validAdvisoryId(value) {
  return typeof value === "string"
    && (/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/.test(value)
      || /^CVE-\d{4}-\d{4,}$/.test(value));
}

function validDateOnly(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

function parseStableVersion(value) {
  if (typeof value !== "string") return null;
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value);
  return match?.slice(1) ?? null;
}

function compareStableVersions(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index].length !== right[index].length) {
      return left[index].length > right[index].length ? 1 : -1;
    }
    if (left[index] !== right[index]) return left[index] > right[index] ? 1 : -1;
  }
  return 0;
}

export function validateAdvisoryExceptionRecords(value) {
  const errors = [];
  const byPackage = new Map();
  if (!Array.isArray(value)) {
    return { errors: ["dependency policy advisoryExceptions must be an array"], byPackage };
  }
  value.forEach((entry, index) => {
    const label = `advisoryExceptions[${index}]`;
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      errors.push(`${label}: record must be an object`);
      return;
    }
    for (const key of Object.keys(entry)) {
      if (!RECORD_KEYS.has(key)) errors.push(`${label}: unknown field ${key}`);
    }
    if (entry.kind !== "direct" && entry.kind !== "transitive") {
      errors.push(`${label}: kind must be "direct" or "transitive"`);
    }
    if (!validPackageName(entry.package)) errors.push(`${label}: package is invalid`);
    if (!Array.isArray(entry.advisoryIds) || entry.advisoryIds.length === 0) {
      errors.push(`${label}: advisoryIds must be a non-empty array`);
    } else {
      const ids = new Set();
      for (const id of entry.advisoryIds) {
        if (!validAdvisoryId(id)) errors.push(`${label}: advisory ID ${String(id)} is invalid`);
        else if (ids.has(id)) errors.push(`${label}: advisory ID ${id} is duplicated`);
        ids.add(id);
      }
    }
    if (parseStableVersion(entry.adoptedVersion) === null) {
      errors.push(`${label}: adoptedVersion must be an exact stable semantic version`);
    }
    if (!validDateOnly(entry.adoptedAt)) errors.push(`${label}: adoptedAt must be a UTC date`);
    if (typeof entry.justification !== "string" || entry.justification.trim() === "") {
      errors.push(`${label}: justification is required`);
    } else if (entry.justification.length > 1000) {
      errors.push(`${label}: justification exceeds 1000 characters`);
    }
    if (validPackageName(entry.package)) {
      if (byPackage.has(entry.package)) errors.push(`${entry.package}: duplicate advisory exception`);
      else byPackage.set(entry.package, entry);
    }
  });
  return { errors, byPackage };
}

export async function workspaceCooldownConfig(root) {
  const source = await readFile(resolve(root, "pnpm-workspace.yaml"), "utf8");
  const lines = source.split(/\r?\n/);
  const ageEntries = lines.filter((line) => /^\s*minimumReleaseAge\s*:/.test(line));
  if (ageEntries.length !== 1) {
    throw new Error("pnpm-workspace.yaml must contain exactly one minimumReleaseAge");
  }
  const ageMatch = /^\s*minimumReleaseAge:\s*(\d+)\s*(?:#.*)?$/.exec(ageEntries[0]);
  if (!ageMatch) throw new Error("pnpm-workspace.yaml minimumReleaseAge must be an integer");

  const excludeEntries = lines.filter((line) => /^\s*minimumReleaseAgeExclude\s*:/.test(line));
  if (excludeEntries.length !== 1) {
    throw new Error("pnpm-workspace.yaml must contain exactly one minimumReleaseAgeExclude");
  }
  const excludeMatch = /^\s*minimumReleaseAgeExclude:\s*(\[[^\n]*\])\s*(?:#.*)?$/.exec(excludeEntries[0]);
  if (!excludeMatch) {
    throw new Error("pnpm-workspace.yaml minimumReleaseAgeExclude must be an inline JSON array");
  }
  let exclusions;
  try {
    exclusions = JSON.parse(excludeMatch[1]);
  } catch {
    throw new Error("pnpm-workspace.yaml minimumReleaseAgeExclude must be valid JSON");
  }
  if (!Array.isArray(exclusions) || exclusions.some((name) => !validPackageName(name))) {
    throw new Error("pnpm-workspace.yaml minimumReleaseAgeExclude must contain only package names");
  }
  if (new Set(exclusions).size !== exclusions.length) {
    throw new Error("pnpm-workspace.yaml minimumReleaseAgeExclude contains duplicates");
  }
  return { minimumAgeMinutes: Number(ageMatch[1]), excludedPackages: new Set(exclusions) };
}

export function validateExceptionBindings({
  byPackage,
  excludedPackages,
  pins,
  packages,
  lockfileVersions,
  now,
}) {
  const errors = [];
  for (const name of excludedPackages) {
    if (!byPackage.has(name)) errors.push(`${name}: workspace age exclusion has no advisory exception record`);
  }
  for (const [name, record] of byPackage) {
    if (!excludedPackages.has(name)) errors.push(`${name}: advisory exception is missing from minimumReleaseAgeExclude`);
    if (name === "pnpm") errors.push("pnpm: package-manager pin is not eligible for a package advisory exception");
    if (Date.parse(`${record.adoptedAt}T00:00:00Z`) > now.getTime()) {
      errors.push(`${name}: advisory exception adoption date is in the future`);
    }
    if (record.kind === "transitive") {
      if (name in pins) errors.push(`${name}: transitive advisory exception must not name a directly pinned package`);
      if (name in packages) errors.push(`${name}: transitive advisory exception must not have a ledger package row`);
      const resolved = lockfileVersions?.get(name);
      if (resolved === undefined) {
        errors.push(`${name}: transitive advisory exception package is missing from the lockfile`);
      } else if (resolved.size !== 1) {
        errors.push(
          `${name}: lockfile resolves ${resolved.size} versions; a transitive exception requires exactly one`,
        );
      } else {
        const [resolvedVersion] = resolved;
        if (record.adoptedVersion !== resolvedVersion) {
          errors.push(
            `${name}: adopted version ${record.adoptedVersion} != lockfile resolution ${resolvedVersion}`,
          );
        }
      }
    } else {
      if (!(name in pins)) errors.push(`${name}: advisory exception package is not directly pinned`);
      if (!(name in packages)) errors.push(`${name}: advisory exception package is missing from the ledger`);
      if (pins[name] !== undefined && record.adoptedVersion !== pins[name]) {
        errors.push(`${name}: adopted version ${record.adoptedVersion} != package pin ${pins[name]}`);
      }
      if (packages[name]?.version !== undefined && record.adoptedVersion !== packages[name].version) {
        errors.push(`${name}: adopted version ${record.adoptedVersion} != ledger ${packages[name].version}`);
      }
    }
  }
  return errors;
}

function advisoryMatchesId(advisory, id) {
  return advisory !== null
    && typeof advisory === "object"
    && !Array.isArray(advisory)
    && (advisory.ghsa_id === id || advisory.cve_id === id);
}

export async function verifyAdvisoryExceptionEvidence(records, fetchJson, fetchImpl, token, errors) {
  await Promise.all(records.map(async (record) => {
    const adoptedVersion = parseStableVersion(record.adoptedVersion);
    const firstPatchedVersions = [];
    let hasInvalidEvidence = adoptedVersion === null;
    await Promise.all(record.advisoryIds.map(async (id) => {
      try {
        const url = id.startsWith("GHSA-")
          ? `https://api.github.com/advisories/${encodeURIComponent(id)}`
          : `https://api.github.com/advisories?cve_id=${encodeURIComponent(id)}`;
        const response = await fetchJson(url, fetchImpl, token);
        const candidates = Array.isArray(response) ? response : [response];
        const advisory = candidates.find((candidate) => advisoryMatchesId(candidate, id));
        if (!advisory) {
          errors.push(`${record.package}: advisory ${id} was not found upstream`);
          hasInvalidEvidence = true;
          return;
        }
        if (!Array.isArray(advisory.vulnerabilities)) {
          errors.push(`${record.package}: advisory ${id} has malformed vulnerability evidence`);
          hasInvalidEvidence = true;
          return;
        }
        const matching = advisory.vulnerabilities.filter((vulnerability) => vulnerability !== null
          && typeof vulnerability === "object"
          && !Array.isArray(vulnerability)
          && vulnerability.package?.ecosystem === "npm"
          && vulnerability.package?.name === record.package);
        if (matching.length === 0) {
          errors.push(`${record.package}: advisory ${id} does not name this npm package`);
          hasInvalidEvidence = true;
          return;
        }
        const unverifiedFix = matching.find(
          (vulnerability) => parseStableVersion(vulnerability.first_patched_version) === null,
        );
        if (adoptedVersion === null || unverifiedFix) {
          errors.push(
            `${record.package}: advisory ${id} has no stable first patched version for the adopted pin`,
          );
          hasInvalidEvidence = true;
          return;
        }
        const parsedFixes = matching.map((vulnerability) => parseStableVersion(
          vulnerability.first_patched_version,
        ));
        const newerFix = parsedFixes.find((fixedVersion) => (
          compareStableVersions(fixedVersion, adoptedVersion) > 0
        ));
        if (newerFix) {
          errors.push(
            `${record.package}: advisory ${id} first patched version ${newerFix.join(".")} is newer than adopted ${record.adoptedVersion}`,
          );
          hasInvalidEvidence = true;
          return;
        }
        firstPatchedVersions.push(...parsedFixes);
      } catch (error) {
        errors.push(`${record.package}: ${id}: ${error instanceof Error ? error.message : "remote verification failed"}`);
        hasInvalidEvidence = true;
      }
    }));
    if (hasInvalidEvidence || firstPatchedVersions.length === 0) return;
    const minimumFix = firstPatchedVersions.reduce((latest, fixedVersion) => (
      compareStableVersions(fixedVersion, latest) > 0 ? fixedVersion : latest
    ));
    if (compareStableVersions(adoptedVersion, minimumFix) !== 0) {
      errors.push(
        `${record.package}: adopted ${record.adoptedVersion} is not the minimum version that fixes all advisories (${minimumFix.join(".")})`,
      );
    }
  }));
}
