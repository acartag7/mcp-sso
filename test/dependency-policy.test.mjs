import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import {
  loadDependencyPolicy,
  verifyLocalDependencyPolicy,
  verifyRemoteDependencyPolicy,
} from "../scripts/check-dependency-policy.mjs";

const ROOT = new URL("..", import.meta.url).pathname;
const NOW = new Date("2026-07-27T12:00:00Z");
const temporaryRoots = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "mcp-sso-dependency-policy-"));
  temporaryRoots.push(root);
  await cp(join(ROOT, "docs"), join(root, "docs"), { recursive: true });
  await cp(join(ROOT, ".github"), join(root, ".github"), { recursive: true });
  await cp(join(ROOT, "package.json"), join(root, "package.json"));
  return root;
}

async function replace(path, before, after) {
  const source = await readFile(path, "utf8");
  assert.ok(source.includes(before), `mutation source contains ${before}`);
  await writeFile(path, source.replace(before, after));
}

test("repository dependency pins match the machine-readable ledger and age floor", async () => {
  await verifyLocalDependencyPolicy(ROOT, NOW);
});

test("CI and publish invoke the remote policy check with a GitHub token", async () => {
  const pkg = JSON.parse(await readFile(join(ROOT, "package.json"), "utf8"));
  assert.equal(pkg.scripts["check:deps"], "node scripts/check-dependency-policy.mjs");
  assert.equal(pkg.scripts["check:deps:remote"], "node scripts/check-dependency-policy.mjs --verify-remote");
  for (const file of ["ci.yml", "publish.yml"]) {
    const workflow = await readFile(join(ROOT, `.github/workflows/${file}`), "utf8");
    assert.match(
      workflow,
      /name: enforce dependency policy\s+env:\s+GITHUB_TOKEN: \$\{\{ github\.token \}\}\s+run: node scripts\/check-dependency-policy\.mjs --verify-remote/,
      `${file} runs the live upstream evidence check`,
    );
  }
});

test("package, action SHA, and action evidence drift each fail closed", async (t) => {
  await t.test("direct package pin", async () => {
    const root = await fixture();
    await replace(join(root, "package.json"), '"hono": "4.12.27"', '"hono": "4.12.26"');
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /hono: package pin 4\.12\.26 != ledger 4\.12\.27/);
  });

  await t.test("optional dependency pin", async () => {
    const root = await fixture();
    const path = join(root, "package.json");
    const pkg = JSON.parse(await readFile(path, "utf8"));
    pkg.optionalDependencies = { undici: "7.16.0" };
    await writeFile(path, `${JSON.stringify(pkg, null, 2)}\n`);
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /undici: direct package pin is missing from the ledger/);
  });

  await t.test("workflow SHA", async () => {
    const root = await fixture();
    await replace(
      join(root, ".github/workflows/ci.yml"),
      "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
      "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    );
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /actions\/checkout pin does not match the ledger/);
  });

  await t.test("version/date comment", async () => {
    const root = await fixture();
    await replace(join(root, ".github/workflows/codeql.yml"), "v6.4.0 (2026-04-20)", "v7.0.0 (2026-07-14)");
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /version\/date comment does not match the ledger/);
  });
});

test("third-party action quarantine rejects a ledger date younger than 15 days", async () => {
  const root = await fixture();
  await replace(
    join(root, "docs/dependency-ledger.md"),
    '"tag": "v7.0.0",\n      "published": "2026-06-18T13:53:05Z"',
    '"tag": "v7.0.0",\n      "published": "2026-07-20T13:53:05Z"',
  );
  await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /actions\/checkout: 2026-07-20T13:53:05Z is younger than 15 days/);
});

test("only the documented first-party repository can claim the age exception", async () => {
  const root = await fixture();
  await replace(
    join(root, "docs/dependency-ledger.md"),
    '"actions/checkout": {\n      "sha":',
    '"actions/checkout": {\n      "firstPartyException": true,\n      "sha":',
  );
  await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /actions\/checkout: is not eligible for the first-party exception/);
});

test("remote evidence binds action tags and npm versions to recorded dates", async () => {
  const policy = await loadDependencyPolicy(ROOT);
  const fetchImpl = async (input) => {
    const url = String(input);
    if (url.includes("api.github.com/repos/")) {
      const action = Object.entries(policy.actions).find(([repo]) => url.includes(`/repos/${repo}/`));
      assert.ok(action, `known action URL: ${url}`);
      const [, record] = action;
      if (url.includes("/releases/tags/")) return Response.json({ published_at: record.published });
      return Response.json({
        sha: record.sha,
        commit: { committer: { date: record.published } },
      });
    }
    const name = decodeURIComponent(new URL(url).pathname.slice(1));
    const record = policy.packages[name];
    assert.ok(record, `known package URL: ${url}`);
    return Response.json({ time: { [record.version]: record.published } });
  };
  await verifyRemoteDependencyPolicy(policy, { fetchImpl, token: "not-a-secret" });

  const badFetch = async (input, init) => {
    const url = String(input);
    if (url.includes("/repos/actions/checkout/commits/")) return Response.json({ sha: "0".repeat(40) });
    return await fetchImpl(input, init);
  };
  await assert.rejects(
    verifyRemoteDependencyPolicy(policy, { fetchImpl: badFetch }),
    /actions\/checkout: v7\.0\.0 does not resolve to the ledger SHA/,
  );
});
