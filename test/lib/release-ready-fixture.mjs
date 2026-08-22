import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluateReleaseReadiness } from "../../scripts/lib/release-ready.mjs";

let repo;
export let ancestor;
export let release;
export let runtimeRelease;
export let evidenceRelease;
export let packageRelease;
export let metadataRelease;
export let versionRelease;
export let buildRelease;
export let unrelated;
export let squashSource;

function git(args) {
  return execFileSync("git", args, { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

export function compatibilityFor(commit) {
  return [
    "# Client compatibility", "", "## Current matrix", "",
    "| Provider | Client | Flow driven | Status | Date | Limits |",
    "| --- | --- | --- | --- | --- | --- |",
    `| Provider | Client | Flow | Verified | 2026-08-22 | Runtime commit \`${commit}\`. |`,
    "", "## Public export live evidence", "",
    "| Export | Live evidence | Runtime commit |", "| --- | --- | --- |",
    `| \`.\` | \`RM.1\` | \`${commit}\` |`,
    `| \`./fastify\` | \`RM.2\` | \`${commit}\` |`,
  ].join("\n");
}

export function statusFor(version = "0.5.0") {
  return [
    "# Current verification status", "", "## Published release", "",
    "| Item | Status |", "| --- | --- |",
    `| npm package and tag | \`mcp-sso@${version}\` and \`v${version}\` |`,
    "| Conformance claim | Current |",
  ].join("\n");
}

export function fixture(overrides = {}) {
  const packageJson = overrides.packageJson ?? { version: "0.5.0", exports: { ".": {}, "./fastify": {} } };
  const releaseMatrix = overrides.releaseMatrix ?? {
    rows: [{ id: "RM.1", exports: ["."] }, { id: "RM.2", exports: ["./fastify"] }],
  };
  const compatibility = overrides.compatibility ?? compatibilityFor(ancestor);
  const status = overrides.status ?? statusFor();
  const releaseCommit = overrides.releaseCommit ?? release;
  return evaluateReleaseReadiness({ packageJson, releaseMatrix, compatibility, status, gitCwd: repo, releaseCommit });
}

export function setupReleaseReadyFixture() {
  repo = mkdtempSync(join(tmpdir(), "mcp-sso-release-ready-"));
  git(["init", "-q"]);
  git(["config", "user.email", "release-ready@example.invalid"]);
  git(["config", "user.name", "Release Ready Test"]);
  writeFileSync(join(repo, "package.json"), JSON.stringify({ version: "0.4.0", scripts: {}, exports: { ".": {} } }));
  git(["add", "package.json"]);
  git(["commit", "-qm", "ancestor"]);
  ancestor = git(["rev-parse", "HEAD"]);
  squashSource = git(["commit-tree", "-m", "squash source", `${ancestor}^{tree}`]);
  git(["commit", "--allow-empty", "-qm", "release"]);
  release = git(["rev-parse", "HEAD"]);
  mkdirSync(join(repo, "src"));
  writeFileSync(join(repo, "src", "runtime.ts"), "export const changed = true;\n");
  git(["add", "src/runtime.ts"]);
  git(["commit", "-qm", "runtime release"]);
  runtimeRelease = git(["rev-parse", "HEAD"]);
  git(["switch", "-q", "-c", "evidence-change", release]);
  for (const directory of ["examples", "test", "scripts/live", ".github/workflows"]) {
    mkdirSync(join(repo, directory), { recursive: true });
  }
  const evidenceFiles = [
    "examples/example.ts", "test/evidence.test.ts", "scripts/live/probe.mjs", "scripts/run-release-matrix.mjs",
    ".github/workflows/publish.yml", "pnpm-lock.yaml", "pnpm-workspace.yaml",
  ];
  for (const file of evidenceFiles) writeFileSync(join(repo, file), "changed\n");
  git(["add", ...evidenceFiles]);
  git(["commit", "-qm", "evidence release"]);
  evidenceRelease = git(["rev-parse", "HEAD"]);
  git(["switch", "-q", "-c", "package-change", release]);
  writeFileSync(join(repo, "package.json"), JSON.stringify({ version: "0.4.0", scripts: {}, exports: { ".": {}, "./new": {} } }));
  git(["commit", "-qam", "package release"]);
  packageRelease = git(["rev-parse", "HEAD"]);
  git(["switch", "-q", "-c", "metadata-change", release]);
  writeFileSync(join(repo, "package.json"), JSON.stringify({
    version: "0.4.0", description: "updated", scripts: { "check:release-ready": "node gate.mjs" }, exports: { ".": {} },
  }));
  git(["commit", "-qam", "metadata release"]);
  metadataRelease = git(["rev-parse", "HEAD"]);
  git(["switch", "-q", "-c", "version-change", release]);
  writeFileSync(join(repo, "package.json"), JSON.stringify({ version: "0.5.0", scripts: {}, exports: { ".": {} } }));
  git(["commit", "-qam", "version release"]);
  versionRelease = git(["rev-parse", "HEAD"]);
  git(["switch", "-q", "-c", "build-change", release]);
  writeFileSync(join(repo, "package.json"), JSON.stringify({
    version: "0.4.0", scripts: { build: "node different-build.mjs" }, exports: { ".": {} },
  }));
  git(["commit", "-qam", "build release"]);
  buildRelease = git(["rev-parse", "HEAD"]);
  git(["switch", "-q", "--orphan", "unrelated"]);
  git(["commit", "--allow-empty", "-qm", "unrelated"]);
  unrelated = git(["rev-parse", "HEAD"]);
}

export function cleanupReleaseReadyFixture() {
  rmSync(repo, { recursive: true, force: true });
}
