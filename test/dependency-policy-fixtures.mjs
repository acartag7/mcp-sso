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
    ...Object.values(policy.transitivePins),
    ...Object.values(policy.actions).filter((record) => record.firstPartyException !== true),
    ...Object.values(policy.tools ?? {}),
    ...Object.values(policy.binaries ?? {}),
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

/** The fast-uri transitive pin the real ledger currently records. Deriving it
 *  keeps these fixtures correct across an advisory bump instead of hardcoding
 *  one version in three files. */
export const FAST_URI_PIN = (await loadDependencyPolicy(ROOT)).transitivePins["fast-uri"].version;

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

/** Edit the workspace exclusion list without assuming its current members. */
export async function setExcludedPackages(root, packages) {
  const workspacePath = join(root, "pnpm-workspace.yaml");
  const source = await readFile(workspacePath, "utf8");
  const replaced = source.replace(
    /^minimumReleaseAgeExclude: \[.*\]$/mu,
    `minimumReleaseAgeExclude: ${JSON.stringify(packages)}`,
  );
  assert.notEqual(replaced, source, "workspace exclusion list found");
  await writeFile(workspacePath, replaced);
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
    await setExcludedPackages(root, []);
  }
  return { policy, youngPublished };
}

async function setLockfileFastUri(root, { version = FAST_URI_PIN, secondVersion = null } = {}) {
  const lockfile = join(root, "pnpm-lock.yaml");
  if (version !== FAST_URI_PIN) {
    await replace(lockfile, `  fast-uri@${FAST_URI_PIN}:\n`, `  fast-uri@${version}:\n`);
    await replace(lockfile, `  fast-uri@${FAST_URI_PIN}: {}`, `  fast-uri@${version}: {}`);
  }
  if (secondVersion !== null) {
    // Model a genuine two-resolution tree: both sections list both versions.
    await replace(lockfile, `  fast-uri@${version}:\n`, `  fast-uri@${version}:\n  fast-uri@${secondVersion}:\n`);
    await replace(lockfile, `  fast-uri@${version}: {}`, `  fast-uri@${version}: {}\n  fast-uri@${secondVersion}: {}`);
  }
}

/** Age the recorded fast-uri transitive pin to one day old, so the 15-day floor
 *  is the only thing that can reject it. Mirrors makeHonoExceptionYoung for the
 *  transitive half of ledger rule 2. */
export async function makeTransitivePinYoung(root) {
  const policy = await loadDependencyPolicy(root);
  const pin = policy.transitivePins["fast-uri"];
  const youngPublished = new Date(NOW.getTime() - DAY_MS).toISOString();
  await replace(
    join(root, "docs/dependency-ledger.md"),
    `"published": "${pin.published}"`,
    `"published": "${youngPublished}"`,
  );
  return { pin, youngPublished };
}

/** Remove any real transitive advisory exception the ledger records for
 *  `packageName`, resetting the workspace exclusion list to hono only. A no-op
 *  when the real ledger records nothing for the package. */
export async function stripTransitiveException(root, packageName = "fast-uri") {
  const ledgerPath = join(root, "docs/dependency-ledger.md");
  const ledger = await readFile(ledgerPath, "utf8");
  const stripped = ledger.replace(new RegExp(
    `(?:\\n    ,|,)?\\n    \\{\\n      "kind": "transitive",\\n      "package": "${packageName}",[\\s\\S]*?\\n    \\}`,
  ), "");
  if (stripped !== ledger) {
    await writeFile(ledgerPath, stripped);
    await setExcludedPackages(root, ["hono"]);
  }
}

export async function makeTransitiveException(root, {
  version = FAST_URI_PIN,
  lockfileVersion = null,
  secondVersion = null,
  packageName = "fast-uri",
} = {}) {
  await stripTransitiveException(root, packageName);
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
  await setExcludedPackages(root, ["hono", packageName]);
  return record;
}
