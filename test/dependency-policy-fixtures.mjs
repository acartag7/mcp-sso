import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach } from "node:test";
import { loadDependencyPolicy } from "../scripts/check-dependency-policy.mjs";

export const ROOT = new URL("..", import.meta.url).pathname;
export const DAY_MS = 86_400_000;
const temporaryRoots = [];

async function conformingNow(root = ROOT) {
  const policy = await loadDependencyPolicy(root);
  const ordinaryRecords = [
    ...Object.values(policy.packages),
    ...Object.values(policy.actions).filter((record) => record.firstPartyException !== true),
  ];
  const newestPublication = Math.max(...ordinaryRecords.map((record) => Date.parse(record.published)));
  const newestAdoption = Math.max(
    ...policy.advisoryExceptions.map((record) => Date.parse(`${record.adoptedAt}T00:00:00Z`)),
    Number.NEGATIVE_INFINITY,
  );
  return new Date(Math.max(
    newestPublication + (policy.minimumAgeDays + 1) * DAY_MS,
    newestAdoption + DAY_MS,
  ));
}

export const NOW = await conformingNow();

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

export async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "mcp-sso-dependency-policy-"));
  temporaryRoots.push(root);
  await cp(join(ROOT, "docs"), join(root, "docs"), { recursive: true });
  await cp(join(ROOT, ".github"), join(root, ".github"), { recursive: true });
  await cp(join(ROOT, "package.json"), join(root, "package.json"));
  await cp(join(ROOT, "pnpm-lock.yaml"), join(root, "pnpm-lock.yaml"));
  await cp(join(ROOT, "pnpm-workspace.yaml"), join(root, "pnpm-workspace.yaml"));
  return root;
}

export async function replace(path, before, after) {
  const source = await readFile(path, "utf8");
  assert.ok(source.includes(before), `mutation source contains ${before}`);
  await writeFile(path, source.replace(before, after));
}

export async function makeHonoExceptionYoung(root, { includeWorkspaceExclusion = true } = {}) {
  const policy = await loadDependencyPolicy(root);
  const hono = policy.packages.hono;
  const youngPublished = new Date(NOW.getTime() - DAY_MS).toISOString();
  await replace(
    join(root, "docs/dependency-ledger.md"),
    `"hono": { "version": "${hono.version}", "published": "${hono.published}" }`,
    `"hono": { "version": "${hono.version}", "published": "${youngPublished}" }`,
  );
  if (!includeWorkspaceExclusion) {
    await replace(
      join(root, "pnpm-workspace.yaml"),
      'minimumReleaseAgeExclude: ["hono"]',
      "minimumReleaseAgeExclude: []",
    );
  }
  return { policy, youngPublished };
}

async function setLockfileFastUri(root, { version = "3.1.5", secondVersion = null } = {}) {
  const lockfile = join(root, "pnpm-lock.yaml");
  await replace(lockfile, "  fast-uri@3.1.2:\n", `  fast-uri@${version}:\n`);
  await replace(lockfile, "  fast-uri@3.1.2: {}", `  fast-uri@${version}: {}`);
  if (secondVersion !== null) {
    // Model a genuine two-resolution tree: both sections list both versions.
    await replace(lockfile, `  fast-uri@${version}:\n`, `  fast-uri@${version}:\n  fast-uri@${secondVersion}:\n`);
    await replace(lockfile, `  fast-uri@${version}: {}`, `  fast-uri@${version}: {}\n  fast-uri@${secondVersion}: {}`);
  }
}

export async function makeTransitiveException(root, {
  version = "3.1.5",
  lockfileVersion = null,
  secondVersion = null,
  packageName = "fast-uri",
} = {}) {
  await setLockfileFastUri(root, { version: lockfileVersion ?? version, secondVersion });
  const record = {
    kind: "transitive",
    package: packageName,
    advisoryIds: [
      "GHSA-4c8g-83qw-93j6",
      "GHSA-v2hh-gcrm-f6hx",
      "GHSA-7p8r-x3mc-p8w7",
    ],
    adoptedVersion: version,
    adoptedAt: "2026-08-15",
    justification: "Published advisory fix; inspected the adopted fast-uri release.",
  };
  await replace(
    join(root, "docs/dependency-ledger.md"),
    '"advisoryExceptions": [',
    `"advisoryExceptions": [\n    ${JSON.stringify(record, null, 2).replaceAll("\n", "\n    ")},`,
  );
  await replace(
    join(root, "pnpm-workspace.yaml"),
    'minimumReleaseAgeExclude: ["hono"]',
    `minimumReleaseAgeExclude: ["hono", "${packageName}"]`,
  );
  return record;
}
