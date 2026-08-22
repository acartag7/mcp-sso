import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { evaluateReleaseReadiness } from "../scripts/lib/release-ready.mjs";

let repo;
let ancestor;
let release;
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
  const releaseMatrix = overrides.releaseMatrix ?? { rows: [{ id: "RM.1" }, { id: "RM.2" }] };
  const compatibility = overrides.compatibility ?? compatibilityFor(ancestor);
  const status = overrides.status ?? statusFor();
  return evaluateReleaseReadiness({ packageJson, releaseMatrix, compatibility, status, gitCwd: repo, releaseCommit: release });
}

before(() => {
  repo = mkdtempSync(join(tmpdir(), "mcp-sso-release-ready-"));
  git(["init", "-q"]);
  git(["config", "user.email", "release-ready@example.invalid"]);
  git(["config", "user.name", "Release Ready Test"]);
  git(["commit", "--allow-empty", "-qm", "ancestor"]);
  ancestor = git(["rev-parse", "HEAD"]);
  git(["commit", "--allow-empty", "-qm", "release"]);
  release = git(["rev-parse", "HEAD"]);
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

test("release ready gate rejects a malformed evidence row beside a valid row", () => {
  const compatibility = `${compatibilityFor(ancestor)}\n| \`./fastify\` | RM.2 | not-a-commit |`;
  const result = fixture({ compatibility });
  assert.ok(result.errors.includes("export evidence: malformed table row for ./fastify"));
});

test("release ready gate does not count table-shaped rows outside the evidence table", () => {
  const row = `| \`./hono\` | \`RM.1\` | \`${ancestor}\` |`;
  const wrappers = [`<!--\n${row}\n-->`, `\`\`\`md\n${row}\n\`\`\``, row];
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

test("release ready gate does not count hidden or out-of-table status rows", () => {
  const base = statusFor().split("\n").filter((line) => !line.includes("npm package and tag")).join("\n");
  const row = "| npm package and tag | `mcp-sso@0.5.0` and `v0.5.0` |";
  const wrappers = [`<!--\n${row}\n-->`, `\`\`\`md\n${row}\n\`\`\``, row];
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
