import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluateReleaseReadiness } from "../../scripts/lib/release-ready.mjs";
import { ROWS } from "../../scripts/live/rehearsal-support.mjs";

let repo;
export let ancestor;
export let release;
export let runtimeRelease;
export let deploymentRelease;
export let harnessRelease;
export let packageRelease;
export let metadataRelease;
export let versionRelease;
export let buildRelease;
export let unrelated;

function git(args) {
  return execFileSync("git", args, { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

/** A rehearsal receipt, in the shape the recorder writes: every row the
 *  rehearsal runs, because the gate re-derives completeness rather than
 *  trusting the receipt's own summary. */
export function receiptFor(commit, overrides = {}) {
  return {
    schema: 1, producer: "rehearsal", runtimeCommit: commit, recordedAt: "2026-08-27T00:00:00.000Z",
    complete: true, rows: ROWS.map((row) => ({ id: row.id, status: "PASS" })),
    releaseMatrix: ["RM.1", "RM.2"],
    ...overrides,
  };
}

/** An operator receipt: a campaign a person drove, covering no export. */
export function operatorReceiptFor(commit, overrides = {}) {
  return {
    schema: 1, producer: "operator", runtimeCommit: commit, recordedAt: "2026-08-27T00:00:00.000Z",
    complete: true, rows: [{ id: "F2", status: "PASS" }],
    ...overrides,
  };
}

/** The active pair, with one side replaced. */
export function receipts({ rehearsal, operator } = {}) {
  return {
    "rehearsal.json": rehearsal ?? receiptFor(ancestor),
    "operator.json": operator ?? operatorReceiptFor(ancestor),
  };
}

export function statusFor(version = "0.5.0") {
  return [
    "# Current verification status", "", "## Published release", "",
    "| Item | Status |", "| --- | --- |",
    `| npm package and tag | \`mcp-sso@${version}\` and \`v${version}\` |`,
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
  const evidence = overrides.receipts ?? receipts();
  const status = overrides.status ?? statusFor();
  const releaseCommit = overrides.releaseCommit ?? release;
  return evaluateReleaseReadiness({ packageJson, releaseMatrix, receipts: evidence, status, gitCwd: repo, releaseCommit });
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

  // Each branch below moves exactly one kind of input, so a test that passes
  // because a neighbouring path changed cannot hide.
  const commitOnly = (name, files, content = "changed\n") => {
    git(["switch", "-q", "-c", name, release]);
    for (const file of files) {
      const directory = file.includes("/") ? file.slice(0, file.lastIndexOf("/")) : "";
      if (directory) mkdirSync(join(repo, directory), { recursive: true });
      writeFileSync(join(repo, file), content);
    }
    git(["add", ...files]);
    git(["commit", "-qm", name]);
    return git(["rev-parse", "HEAD"]);
  };

  runtimeRelease = commitOnly("runtime-change", ["src/runtime.ts"], "export const changed = true;\n");
  deploymentRelease = commitOnly("deployment-change", ["scripts/live/serve.sh", "scripts/live/run.sh", "scripts/live/run-support.mjs"]);
  // Evidence-producing code: it ages a rehearsal receipt, which one dispatch
  // rewrites, and never an operator's, which no probe produced.
  harnessRelease = commitOnly("harness-change", ["scripts/live/probe-entra.mjs", "scripts/live/rehearsal.mjs", "test/some.test.mjs", "docs/verification.md"]);

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
  if (repo) rmSync(repo, { recursive: true, force: true });
}
