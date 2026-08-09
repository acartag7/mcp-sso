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
const DAY_MS = 86_400_000;
const temporaryRoots = [];

async function conformingNow(root = ROOT) {
  const policy = await loadDependencyPolicy(root);
  const ordinaryRecords = [
    ...Object.values(policy.packages),
    ...Object.values(policy.actions).filter((record) => record.firstPartyException !== true),
  ];
  const newestPublication = Math.max(...ordinaryRecords.map((record) => Date.parse(record.published)));
  return new Date(newestPublication + (policy.minimumAgeDays + 1) * DAY_MS);
}

const NOW = await conformingNow();

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "mcp-sso-dependency-policy-"));
  temporaryRoots.push(root);
  await cp(join(ROOT, "docs"), join(root, "docs"), { recursive: true });
  await cp(join(ROOT, ".github"), join(root, ".github"), { recursive: true });
  await cp(join(ROOT, "package.json"), join(root, "package.json"));
  await cp(join(ROOT, "pnpm-workspace.yaml"), join(root, "pnpm-workspace.yaml"));
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
    const policy = await loadDependencyPolicy(root);
    await replace(
      join(root, "package.json"),
      `"hono": "${policy.packages.hono.version}"`,
      '"hono": "0.0.0"',
    );
    await assert.rejects(
      verifyLocalDependencyPolicy(root, NOW),
      new RegExp(`hono: package pin 0\\.0\\.0 != ledger ${policy.packages.hono.version.replaceAll(".", "\\.")}`),
    );
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
    const policy = await loadDependencyPolicy(root);
    await replace(
      join(root, ".github/workflows/ci.yml"),
      `actions/checkout@${policy.actions["actions/checkout"].sha}`,
      `actions/checkout@${"0".repeat(40)}`,
    );
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /actions\/checkout pin does not match the ledger/);
  });

  await t.test("version/date comment", async () => {
    const root = await fixture();
    const policy = await loadDependencyPolicy(root);
    const setupNode = policy.actions["actions/setup-node"];
    await replace(
      join(root, ".github/workflows/codeql.yml"),
      `${setupNode.tag} (${setupNode.published.slice(0, 10)})`,
      "bogus action evidence",
    );
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /version\/date comment does not match the ledger/);
  });
});

test("third-party action quarantine rejects a ledger date younger than 15 days", async () => {
  const root = await fixture();
  const policy = await loadDependencyPolicy(root);
  const checkout = policy.actions["actions/checkout"];
  const youngPublished = new Date(NOW.getTime() - DAY_MS).toISOString();
  await replace(
    join(root, "docs/dependency-ledger.md"),
    `"tag": "${checkout.tag}",\n      "published": "${checkout.published}"`,
    `"tag": "${checkout.tag}",\n      "published": "${youngPublished}"`,
  );
  await assert.rejects(
    verifyLocalDependencyPolicy(root, NOW),
    (error) => error instanceof Error
      && error.message.includes(`actions/checkout: ${youngPublished} is younger than ${policy.minimumAgeDays} days`),
  );
});

test("workspace and workflow pnpm settings cannot bypass the recorded pins", async (t) => {
  await t.test("workspace age floor", async () => {
    const root = await fixture();
    await replace(join(root, "pnpm-workspace.yaml"), "minimumReleaseAge: 21600", "minimumReleaseAge: 0");
    await assert.rejects(
      verifyLocalDependencyPolicy(root, NOW),
      /pnpm-workspace\.yaml minimumReleaseAge 0 != ledger 21600/,
    );
  });

  await t.test("workflow version override", async () => {
    const root = await fixture();
    const policy = await loadDependencyPolicy(root);
    const pnpmSetup = policy.actions["pnpm/action-setup"];
    const pin = `pnpm/action-setup@${pnpmSetup.sha} # ${pnpmSetup.tag} (${pnpmSetup.published.slice(0, 10)})`;
    await replace(
      join(root, ".github/workflows/ci.yml"),
      pin,
      `${pin}\n        with:\n          version: 11.0.0`,
    );
    await assert.rejects(
      verifyLocalDependencyPolicy(root, NOW),
      /pnpm\/action-setup must read packageManager without a version override/,
    );
  });
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
    (error) => error instanceof Error
      && error.message.includes(`actions/checkout: ${policy.actions["actions/checkout"].tag} does not resolve to the ledger SHA`),
  );
});
