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
  await cp(join(ROOT, "pnpm-workspace.yaml"), join(root, "pnpm-workspace.yaml"));
  return root;
}

export async function replace(path, before, after) {
  const source = await readFile(path, "utf8");
  assert.ok(source.includes(before), `mutation source contains ${before}`);
  await writeFile(path, source.replace(before, after));
}

export async function addYoungHonoException(root, { includeWorkspaceExclusion = true } = {}) {
  const policy = await loadDependencyPolicy(root);
  const hono = policy.packages.hono;
  const youngPublished = new Date(NOW.getTime() - DAY_MS).toISOString();
  const record = {
    package: "hono",
    advisoryIds: ["GHSA-54fx-42gc-7vw4"],
    adoptedVersion: hono.version,
    adoptedAt: NOW.toISOString().slice(0, 10),
    justification: "Published advisory fix; inspected the adopted Hono release.",
  };
  await replace(
    join(root, "docs/dependency-ledger.md"),
    '"advisoryExceptions": [],',
    `"advisoryExceptions": ${JSON.stringify([record], null, 2)},`,
  );
  await replace(
    join(root, "docs/dependency-ledger.md"),
    `"hono": { "version": "${hono.version}", "published": "${hono.published}" }`,
    `"hono": { "version": "${hono.version}", "published": "${youngPublished}" }`,
  );
  if (includeWorkspaceExclusion) {
    await replace(
      join(root, "pnpm-workspace.yaml"),
      "minimumReleaseAgeExclude: []",
      'minimumReleaseAgeExclude: ["hono"]',
    );
  }
  return { policy, youngPublished };
}
