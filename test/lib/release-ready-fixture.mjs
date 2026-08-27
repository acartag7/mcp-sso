import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evidenceInputDigest } from "../../scripts/lib/release-evidence-git.mjs";
import { PROVIDER_ROWS } from "../../scripts/live/render-evidence.mjs";
import { evaluateReleaseReadiness } from "../../scripts/lib/release-ready.mjs";

let repo;
export let ancestor;
export let release;
export let runtimeRelease;
export let evidenceRelease;
export let modeRelease;
export let packageRelease;
export let metadataRelease;
export let versionRelease;
export let buildRelease;
export let harnessRelease;
export let deploymentRelease;
export let rowDefinitionRelease;
export let unrelated;

function git(args) {
  return execFileSync("git", args, { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

/** `provider` is the commit the matrix row names, `exportCommit` the one the
 *  export table names, so a test can age one without the other. `rendered`
 *  makes the provider row one the record run writes rather than one an
 *  operator recorded. */
export function compatibilityFor(commit, { exportCommit = commit, rendered = false } = {}) {
  const row = rendered
    ? `| Provider | Client | Flow | rehearsal | Verified | 2026-08-22 | Runtime commit \`${commit}\`. |`
    : `| Provider | Client | Flow | operator | Verified | 2026-08-22 | Runtime commit \`${commit}\`. |`;
  return [
    "# Client compatibility", "", "## Current matrix", "",
    "| Provider | Client | Flow driven | Recorded by | Status | Date | Limits |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    row,
    "", "## Public export live evidence", "",
    "| Export | Live evidence | Runtime commit |", "| --- | --- | --- |",
    `| \`.\` | \`RM.1\` | \`${exportCommit}\` |`,
    `| \`./fastify\` | \`RM.2\` | \`${exportCommit}\` |`,
  ].join("\n");
}

export function evidenceDigestFor(commit) {
  return evidenceInputDigest(repo, commit);
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
    rows: [
      { id: "RM.1", title: "Root flow", packedArtifact: true, exports: ["."], evidence: [{ file: "test/root.test.ts", name: "root flow" }] },
      { id: "RM.2", title: "Fastify flow", packedArtifact: true, exports: ["./fastify"], evidence: [{ file: "test/fastify.test.ts", name: "fastify flow" }] },
    ],
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
  git(["commit", "--allow-empty", "-qm", "release"]);
  release = git(["rev-parse", "HEAD"]);
  mkdirSync(join(repo, "src"));
  writeFileSync(join(repo, "src", "runtime.ts"), "export const changed = true;\n");
  git(["add", "src/runtime.ts"]);
  git(["commit", "-qm", "runtime release"]);
  runtimeRelease = git(["rev-parse", "HEAD"]);
  git(["switch", "-q", "-c", "evidence-change", release]);
  for (const directory of ["examples", "test", "scripts/live", "scripts/lib", "docs", ".github/workflows"]) {
    mkdirSync(join(repo, directory), { recursive: true });
  }
  const evidenceFiles = [
    "examples/example.ts", "test/evidence.test.ts", "scripts/live/probe.mjs", "scripts/run-release-matrix.mjs",
    "scripts/check-release-matrix.mjs", "scripts/lib/release-matrix-outcome.mjs", "docs/verification.md",
    ".github/workflows/publish.yml", "pnpm-lock.yaml", "pnpm-workspace.yaml",
  ];
  for (const file of evidenceFiles) writeFileSync(join(repo, file), "changed\n");
  git(["add", ...evidenceFiles]);
  git(["commit", "-qm", "evidence release"]);
  evidenceRelease = git(["rev-parse", "HEAD"]);
  chmodSync(join(repo, "scripts/live/probe.mjs"), 0o755);
  git(["add", "scripts/live/probe.mjs"]);
  git(["commit", "-qm", "evidence mode release"]);
  modeRelease = git(["rev-parse", "HEAD"]);
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
  // Only the harness moves here: what produces evidence, never what a client
  // would observe.
  git(["switch", "-q", "-c", "harness-change", release]);
  for (const directory of ["test", "scripts/live", "docs", ".github/workflows"]) mkdirSync(join(repo, directory), { recursive: true });
  const harnessFiles = ["test/evidence.test.ts", "scripts/live/probe.mjs", "docs/verification.md", ".github/workflows/live.yml"];
  for (const file of harnessFiles) writeFileSync(join(repo, file), "harness changed\n");
  git(["add", ...harnessFiles]);
  git(["commit", "-qm", "harness release"]);
  harnessRelease = git(["rev-parse", "HEAD"]);
  // The leg itself moves: what a client is pointed at, not what watches it.
  git(["switch", "-q", "-c", "deployment-change", release]);
  mkdirSync(join(repo, "scripts/live"), { recursive: true });
  writeFileSync(join(repo, "scripts/live/serve.sh"), "serve differently\n");
  git(["add", "scripts/live/serve.sh"]);
  git(["commit", "-qm", "deployment release"]);
  deploymentRelease = git(["rev-parse", "HEAD"]);
  // The definition of what the record run renders moves.
  git(["switch", "-q", "-c", "row-definition-change", release]);
  mkdirSync(join(repo, "scripts/live"), { recursive: true });
  writeFileSync(join(repo, "scripts/live/render-evidence.mjs"), "export const PROVIDER_ROWS = [];\n");
  git(["add", "scripts/live/render-evidence.mjs"]);
  git(["commit", "-qm", "row definition release"]);
  rowDefinitionRelease = git(["rev-parse", "HEAD"]);
  git(["switch", "-q", "--orphan", "unrelated"]);
  git(["commit", "--allow-empty", "-qm", "unrelated"]);
  unrelated = git(["rev-parse", "HEAD"]);
}

export function cleanupReleaseReadyFixture() {
  rmSync(repo, { recursive: true, force: true });
}
