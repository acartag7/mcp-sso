import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { evaluateReleaseReadiness } from "../scripts/lib/release-ready.mjs";

let repo;
let ancestor;
let release;
let runtimeRelease;
let evidenceRelease;
let packageRelease;
let metadataRelease;
let buildRelease;
let unrelated;

function git(args) {
  return execFileSync("git", args, { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function compatibilityFor(commit) {
  return [
    "# Client compatibility",
    "",
    `Runtime commit \`${commit}\`.`,
    "",
    "## Public export live evidence",
    "",
    "| Export | Live evidence | Runtime commit |",
    "| --- | --- | --- |",
    `| \`.\` | \`RM.1\` | \`${commit}\` |`,
    `| \`./fastify\` | \`RM.2\` | \`${commit}\` |`,
  ].join("\n");
}

function statusFor(version = "0.5.0") {
  return [
    "# Current verification status",
    "",
    "## Published release",
    "",
    "| Item | Status |",
    "| --- | --- |",
    `| npm package and tag | \`mcp-sso@${version}\` and \`v${version}\` |`,
    "| Conformance claim | Current |",
  ].join("\n");
}

function fixture(overrides = {}) {
  const packageJson = overrides.packageJson ?? { version: "0.5.0", exports: { ".": {}, "./fastify": {} } };
  const releaseMatrix = overrides.releaseMatrix ?? {
    rows: [{ id: "RM.1", exports: ["."] }, { id: "RM.2", exports: ["./fastify"] }],
  };
  const compatibility = overrides.compatibility ?? compatibilityFor(ancestor);
  const status = overrides.status ?? statusFor();
  const releaseCommit = overrides.releaseCommit ?? release;
  return evaluateReleaseReadiness({ packageJson, releaseMatrix, compatibility, status, gitCwd: repo, releaseCommit });
}

before(() => {
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
  for (const directory of ["examples", "test", "scripts/live", ".github/workflows"]) {
    mkdirSync(join(repo, directory), { recursive: true });
  }
  const evidenceFiles = [
    "examples/example.ts", "test/evidence.test.ts", "scripts/live/probe.mjs", "scripts/run-release-matrix.mjs",
    ".github/workflows/publish.yml", "pnpm-lock.yaml", "pnpm-workspace.yaml", "tsconfig.json", "tsconfig.build.json",
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
    version: "0.5.0",
    description: "updated",
    scripts: { "check:release-ready": "node gate.mjs" },
    exports: { ".": {} },
  }));
  git(["commit", "-qam", "metadata release"]);
  metadataRelease = git(["rev-parse", "HEAD"]);
  git(["switch", "-q", "-c", "build-change", release]);
  writeFileSync(join(repo, "package.json"), JSON.stringify({
    version: "0.4.0",
    scripts: { build: "node different-build.mjs" },
    exports: { ".": {} },
  }));
  git(["commit", "-qam", "build release"]);
  buildRelease = git(["rev-parse", "HEAD"]);
  git(["switch", "-q", "--orphan", "unrelated"]);
  git(["commit", "--allow-empty", "-qm", "unrelated"]);
  unrelated = git(["rev-parse", "HEAD"]);
});

after(() => rmSync(repo, { recursive: true, force: true }));

test("release ready gate accepts complete evidence at an ancestor commit", () => {
  assert.deepEqual(fixture().errors, []);
});

test("release ready gate names a runtime commit outside the release history", () => {
  const result = fixture({ compatibility: compatibilityFor(unrelated) });
  assert.ok(result.errors.includes(`recorded runtime commit ${unrelated} is not an ancestor of release commit ${release}`));
});

test("release ready gate rejects runtime changes after the evidence commit", () => {
  const result = fixture({ releaseCommit: runtimeRelease });
  assert.ok(result.errors.includes(
    `recorded runtime commit ${ancestor} predates release runtime changes: src/runtime.ts`,
  ));
});

test("release ready gate rejects evidence-definition changes after the evidence commit", () => {
  const result = fixture({ releaseCommit: evidenceRelease });
  const error = result.errors.find((message) => message.startsWith(`recorded runtime commit ${ancestor} predates`));
  assert.ok(error);
  for (const file of [
    "examples/example.ts", "scripts/live/probe.mjs", "scripts/run-release-matrix.mjs", "test/evidence.test.ts",
    ".github/workflows/publish.yml", "pnpm-lock.yaml", "pnpm-workspace.yaml", "tsconfig.build.json", "tsconfig.json",
  ]) assert.match(error, new RegExp(file.replaceAll(".", "\\.")));
});

test("release ready gate rejects package runtime changes after the evidence commit", () => {
  const result = fixture({ releaseCommit: packageRelease });
  assert.ok(result.errors.includes(
    `recorded runtime commit ${ancestor} predates release runtime changes: package.json:exports`,
  ));
});

test("release ready gate permits release metadata after the evidence commit", () => {
  assert.deepEqual(fixture({ releaseCommit: metadataRelease }).errors, []);
});

test("release ready gate rejects a build-command change after the evidence commit", () => {
  const result = fixture({ releaseCommit: buildRelease });
  assert.ok(result.errors.includes(
    `recorded runtime commit ${ancestor} predates release runtime changes: package.json:scripts`,
  ));
});

test("release ready gate checks the recorded main commit for a squash-merged live tree", () => {
  const compatibility = compatibilityFor(ancestor).replace(
    `Runtime commit \`${ancestor}\`.`,
    `Runtime commit \`${unrelated}\`, later merged without runtime changes as \`${ancestor}\`.`,
  );
  assert.deepEqual(fixture({ compatibility }).errors, []);
});

test("release ready gate names a public export without a live evidence row", () => {
  const result = fixture({ packageJson: { version: "0.5.0", exports: { ".": {}, "./fastify": {}, "./hono": {} } } });
  assert.ok(result.errors.includes("missing live evidence row for export ./hono"));
});

test("release ready gate names an evidence ID absent from the release matrix", () => {
  const compatibility = compatibilityFor(ancestor).replace("`RM.2`", "`RM.999`");
  const result = fixture({ compatibility });
  assert.ok(result.errors.includes("unknown live evidence ID RM.999 for export ./fastify"));
});

test("release ready gate rejects an existing evidence row that does not cover the export", () => {
  const compatibility = compatibilityFor(ancestor).replace(
    `| \`./fastify\` | \`RM.2\` |`,
    `| \`./fastify\` | \`RM.1\` |`,
  );
  const result = fixture({ compatibility });
  assert.ok(result.errors.includes("live evidence ID RM.1 does not cover export ./fastify"));
});

test("release ready gate rejects a malformed evidence row beside a valid row", () => {
  const compatibility = `${compatibilityFor(ancestor)}\n| \`./fastify\` | RM.2 | not-a-commit |`;
  const result = fixture({ compatibility });
  assert.ok(result.errors.includes("export evidence: malformed table row for ./fastify"));
});

test("release ready gate does not count table-shaped rows outside the evidence table", () => {
  const row = `| \`./hono\` | \`RM.1\` | \`${ancestor}\` |`;
  const wrappers = [`<!--\n${row}\n-->`, `\`\`\`md\n${row}\n\`\`\``, `> ${row}`, row];
  for (const wrapped of wrappers) {
    const compatibility = `${compatibilityFor(ancestor)}\n\n${wrapped}`;
    const result = fixture({
      compatibility,
      packageJson: { version: "0.5.0", exports: { ".": {}, "./fastify": {}, "./hono": {} } },
    });
    assert.ok(result.errors.includes("missing live evidence row for export ./hono"));
    assert.ok(result.errors.includes("export evidence: table-shaped row outside the rendered table"));
  }
});

test("release ready gate rejects an evidence table hidden by Markdown", () => {
  const source = compatibilityFor(ancestor);
  const tableStart = "| Export | Live evidence | Runtime commit |";
  const cases = [
    source.replace(tableStart, `<!--\n${tableStart}`) + "\n-->",
    source.replace(tableStart, `\`\`\`md\n${tableStart}`) + "\n\`\`\`",
  ];
  const expected = [
    "export evidence: HTML comments are not allowed in the table section",
    "export evidence: fenced blocks are not allowed in the table section",
  ];
  for (const [index, compatibility] of cases.entries()) {
    assert.ok(fixture({ compatibility }).errors.includes(expected[index]));
  }
});

test("release ready gate rejects repeated evidence and status sections", () => {
  for (const suffix of ["", " ", " ##"]) {
    const compatibility = `${compatibilityFor(ancestor)}\n\n## Public export live evidence${suffix}`;
    assert.ok(fixture({ compatibility }).errors.includes(
      "export evidence: expected one canonical ## Public export live evidence section, found 2",
    ));
    const status = `${statusFor()}\n\n## Published release${suffix}`;
    assert.ok(fixture({ status }).errors.includes(
      "status version: expected one canonical ## Published release section, found 2",
    ));
  }
});

test("release ready gate does not count hidden or out-of-table status rows", () => {
  const base = statusFor().split("\n").filter((line) => !line.includes("npm package and tag")).join("\n");
  const row = "| npm package and tag | `mcp-sso@0.5.0` and `v0.5.0` |";
  const wrappers = [`<!--\n${row}\n-->`, `\`\`\`md\n${row}\n\`\`\``, `> ${row}`, row];
  for (const wrapped of wrappers) {
    const result = fixture({ status: `${base}\n\n${wrapped}` });
    assert.ok(result.errors.includes("status version: expected one npm package and tag row, found 0"));
    assert.ok(result.errors.includes("status version: table-shaped row outside the rendered table"));
  }
});

test("release ready gate rejects a status table hidden by Markdown", () => {
  const source = statusFor();
  const tableStart = "| Item | Status |";
  const cases = [
    source.replace(tableStart, `<!--\n${tableStart}`) + "\n-->",
    source.replace(tableStart, `\`\`\`md\n${tableStart}`) + "\n\`\`\`",
  ];
  const expected = [
    "status version: HTML comments are not allowed in the table section",
    "status version: fenced blocks are not allowed in the table section",
  ];
  for (const [index, status] of cases.entries()) {
    assert.ok(fixture({ status }).errors.includes(expected[index]));
  }
});

test("release ready gate rejects every malformed or duplicate named status row", () => {
  const malformed = `${statusFor()}\n| npm package and tag | mcp-sso@0.4.0 and v0.4.0 |`;
  assert.ok(fixture({ status: malformed }).errors.includes("status version: malformed npm package and tag row"));
  const conflicting = `${statusFor()}\n| npm package and tag | \`mcp-sso@0.4.0\` and \`v0.4.0\` |`;
  assert.ok(fixture({ status: conflicting }).errors.includes(
    "status version: expected one npm package and tag row, found 2",
  ));
  for (const label of [
    "**npm package and tag**", "npm  package and tag", "npm&nbsp;package and tag", "npm package and tag ",
  ]) {
    const decorated = `${statusFor()}\n| ${label} | \`mcp-sso@9.9.9\` and \`v9.9.9\` |`;
    assert.ok(fixture({ status: decorated }).errors.includes("status version: malformed item label"));
  }
  const wrongCase = `${statusFor()}\n| NPM package and tag | \`mcp-sso@9.9.9\` and \`v9.9.9\` |`;
  assert.ok(fixture({ status: wrongCase }).errors.includes("status version: malformed npm package and tag row"));
});

test("release ready gate ignores the status label in prose", () => {
  const status = `${statusFor()}\n\nThe npm package and tag are published together.`;
  assert.deepEqual(fixture({ status }).errors, []);
});

test("release ready gate reports package and status versions", () => {
  const result = fixture({ packageJson: { version: "0.5.1", exports: { ".": {}, "./fastify": {} } } });
  assert.ok(result.errors.includes("version mismatch: package.json is 0.5.1, docs/verification-status.md is 0.5.0"));
});

test("publish runs release readiness with full git history and ordinary tests do not", async () => {
  const { readFile } = await import("node:fs/promises");
  const root = new URL("..", import.meta.url);
  const workflow = await readFile(new URL(".github/workflows/publish.yml", root), "utf8");
  const packageJson = JSON.parse(await readFile(new URL("package.json", root), "utf8"));
  assert.match(workflow, /fetch-depth: 0/);
  assert.match(workflow, /run: pnpm check:release-ready/);
  assert.ok(workflow.indexOf("run: pnpm check:release-ready") < workflow.indexOf("run: pnpm install --frozen-lockfile"));
  assert.equal(packageJson.scripts.test.includes("check:release-ready"), false);
});
