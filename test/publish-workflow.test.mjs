import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const ROOT = new URL("..", import.meta.url).pathname;
const WORKFLOW = await readFile(`${ROOT}/.github/workflows/publish.yml`, "utf8");

function job(name) {
  const match = new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [a-z][a-z-]*:\\n|(?![\\s\\S]))`, "m").exec(WORKFLOW);
  assert.ok(match, `${name} job exists`);
  return match[0];
}

test("manual dispatch has no real-publish input and reaches only the dry-run job", () => {
  assert.match(WORKFLOW, /^  workflow_dispatch:\s*$/m);
  assert.doesNotMatch(WORKFLOW, /dry_run:/);
  const dryRun = job("dry-run");
  assert.match(dryRun, /if: github\.event_name == 'workflow_dispatch'/);
  assert.match(dryRun, /permissions: \{\}/);
  assert.match(dryRun, /npm publish .+ --dry-run --ignore-scripts/);
  assert.doesNotMatch(dryRun, /id-token|--provenance|environment: publish/);
});

test("build is read-only, version-bound, and uploads one digest-bound tarball", () => {
  const build = job("build");
  assert.match(build, /permissions:\n      contents: read/);
  assert.match(build, /persist-credentials: false/);
  assert.match(build, /test "\$RELEASE_TAG" = "v\$PACKAGE_VERSION"/);
  assert.match(build, /npm pack --ignore-scripts --json/);
  assert.match(build, /shasum -a 256 "\$TARBALL" > "\$TARBALL\.sha256"/);
  assert.match(build, /actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/);
  assert.doesNotMatch(build, /id-token: write|contents: write/);
});

test("OIDC publish consumes the artifact without checkout, install, or repository scripts", () => {
  const publish = job("publish");
  assert.match(publish, /if: github\.event_name == 'push'/);
  assert.match(publish, /environment: publish/);
  assert.match(publish, /permissions:\n      id-token: write/);
  assert.match(publish, /actions\/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c/);
  assert.match(publish, /shasum -a 256 -c mcp-sso-\*\.tgz\.sha256/);
  assert.match(publish, /npm publish .+ --provenance --ignore-scripts/);
  assert.doesNotMatch(publish, /actions\/checkout|pnpm |npm install|contents: write/);
});

test("GitHub Release authority is separate and has no OIDC permission", () => {
  const release = job("release");
  assert.match(release, /needs: publish/);
  assert.match(release, /permissions:\n      contents: write/);
  assert.match(release, /GH_REPO: \$\{\{ github\.repository \}\}/);
  assert.match(release, /gh release create "\$TAG"/);
  assert.doesNotMatch(release, /id-token|npm publish|actions\/checkout/);
});
