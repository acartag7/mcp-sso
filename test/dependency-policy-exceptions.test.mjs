import assert from "node:assert/strict";
import { join } from "node:path";
import { test } from "node:test";
import {
  loadDependencyPolicy,
  verifyLocalDependencyPolicy,
  verifyRemoteDependencyPolicy,
} from "../scripts/check-dependency-policy.mjs";
import {
  makeHonoExceptionYoung,
  fixture,
  NOW,
  replace,
  ROOT,
} from "./dependency-policy-fixtures.mjs";

test("a recorded advisory exception bypasses the floor only for its exact package pin", async () => {
  const root = await fixture();
  await makeHonoExceptionYoung(root);
  await verifyLocalDependencyPolicy(root, NOW);
});

test("workspace and ledger advisory-exception layers cannot diverge", async (t) => {
  await t.test("unrecorded workspace exclusion", async () => {
    const root = await fixture();
    await replace(
      join(root, "pnpm-workspace.yaml"),
      'minimumReleaseAgeExclude: ["hono"]',
      'minimumReleaseAgeExclude: ["hono", "express"]',
    );
    await assert.rejects(
      verifyLocalDependencyPolicy(root, NOW),
      /express: workspace age exclusion has no advisory exception record/,
    );
  });

  await t.test("record without workspace exclusion", async () => {
    const root = await fixture();
    await makeHonoExceptionYoung(root, { includeWorkspaceExclusion: false });
    await assert.rejects(
      verifyLocalDependencyPolicy(root, NOW),
      /hono: advisory exception is missing from minimumReleaseAgeExclude/,
    );
  });

  await t.test("record cannot survive a later pin change", async () => {
    const root = await fixture();
    const { policy } = await makeHonoExceptionYoung(root);
    await replace(
      join(root, "package.json"),
      `"hono": "${policy.packages.hono.version}"`,
      '"hono": "0.0.0"',
    );
    await assert.rejects(
      verifyLocalDependencyPolicy(root, NOW),
      /hono: adopted version .* != package pin 0\.0\.0/,
    );
  });

  await t.test("package-manager pseudo-pin", async () => {
    const root = await fixture();
    const policy = await loadDependencyPolicy(root);
    const record = {
      package: "pnpm",
      advisoryIds: ["GHSA-54fx-42gc-7vw4"],
      adoptedVersion: policy.packages.pnpm.version,
      adoptedAt: NOW.toISOString().slice(0, 10),
      justification: "Must not be accepted: pnpm is a manager pin, not an installable dependency.",
    };
    await replace(
      join(root, "docs/dependency-ledger.md"),
      '"advisoryExceptions": [',
      `"advisoryExceptions": [\n${JSON.stringify(record, null, 2).replaceAll("\n", "\n    ")},`,
    );
    await replace(
      join(root, "pnpm-workspace.yaml"),
      'minimumReleaseAgeExclude: ["hono"]',
      'minimumReleaseAgeExclude: ["pnpm", "hono"]',
    );
    await assert.rejects(
      verifyLocalDependencyPolicy(root, NOW),
      /pnpm: package-manager pin is not eligible for a package advisory exception/,
    );
  });

  await t.test("unknown record field", async () => {
    const root = await fixture();
    const policy = await loadDependencyPolicy(root);
    const exception = policy.advisoryExceptions.find((record) => record.package === "hono");
    assert.ok(exception, "Hono advisory exception is present in the repository fixture");
    await replace(
      join(root, "docs/dependency-ledger.md"),
      `"justification": "${exception.justification}"\n    }`,
      `"justification": "${exception.justification}",\n      "unexpected": true\n    }`,
    );
    await assert.rejects(
      verifyLocalDependencyPolicy(root, NOW),
      /advisoryExceptions\[0\]: unknown field unexpected/,
    );
  });
});

function upstreamFetch(policy, {
  advisoryPackage = "hono",
  fixedVersion = policy.packages.hono.version,
  fixedVersions = {},
} = {}) {
  return async (input) => {
    const url = String(input);
    if (url.includes("api.github.com/advisories")) {
      const parsed = new URL(url);
      const advisoryId = parsed.pathname.startsWith("/advisories/")
        ? decodeURIComponent(parsed.pathname.slice("/advisories/".length))
        : parsed.searchParams.get("cve_id");
      assert.ok(advisoryId, `advisory ID present: ${url}`);
      return Response.json({
        ghsa_id: advisoryId.startsWith("GHSA-") ? advisoryId : "GHSA-54fx-42gc-7vw4",
        cve_id: advisoryId.startsWith("CVE-") ? advisoryId : null,
        vulnerabilities: [{
          package: { ecosystem: "npm", name: advisoryPackage },
          first_patched_version: fixedVersions[advisoryId] ?? fixedVersion,
        }],
      });
    }
    if (url.includes("api.github.com/repos/")) {
      const action = Object.entries(policy.actions).find(([repo]) => url.includes(`/repos/${repo}/`));
      assert.ok(action, `known action URL: ${url}`);
      const [, record] = action;
      if (url.includes("/releases/tags/")) return Response.json({ published_at: record.published });
      return Response.json({ sha: record.sha, commit: { committer: { date: record.published } } });
    }
    const name = decodeURIComponent(new URL(url).pathname.slice(1));
    const record = policy.packages[name];
    assert.ok(record, `known package URL: ${url}`);
    return Response.json({ time: { [record.version]: record.published } });
  };
}

test("remote advisory evidence binds the package and first patched version", async (t) => {
  const policy = await loadDependencyPolicy(ROOT);
  const exceptionPolicy = structuredClone(policy);
  exceptionPolicy.advisoryExceptions = [{
    package: "hono",
    advisoryIds: ["GHSA-54fx-42gc-7vw4"],
    adoptedVersion: policy.packages.hono.version,
    adoptedAt: NOW.toISOString().slice(0, 10),
    justification: "Published advisory fix; inspected the adopted Hono release.",
  }];
  await verifyRemoteDependencyPolicy(exceptionPolicy, {
    fetchImpl: upstreamFetch(policy),
    token: "not-a-secret",
  });

  await t.test("CVE lookup", async () => {
    const cvePolicy = structuredClone(exceptionPolicy);
    cvePolicy.advisoryExceptions[0].advisoryIds = ["CVE-2026-71848"];
    await verifyRemoteDependencyPolicy(cvePolicy, {
      fetchImpl: upstreamFetch(policy),
      token: "not-a-secret",
    });
  });

  await t.test("later adopted version fixes every recorded advisory", async () => {
    const combinedPolicy = structuredClone(exceptionPolicy);
    combinedPolicy.packages.hono.version = "4.12.34";
    combinedPolicy.advisoryExceptions[0].adoptedVersion = "4.12.34";
    combinedPolicy.advisoryExceptions[0].advisoryIds = [
      "GHSA-aaaa-bbbb-cccc",
      "GHSA-dddd-eeee-ffff",
    ];
    await verifyRemoteDependencyPolicy(combinedPolicy, {
      fetchImpl: upstreamFetch(combinedPolicy, {
        fixedVersions: {
          "GHSA-aaaa-bbbb-cccc": "4.12.33",
          "GHSA-dddd-eeee-ffff": "4.12.34",
        },
      }),
      token: "not-a-secret",
    });
  });

  await t.test("wrong package", async () => {
    await assert.rejects(
      verifyRemoteDependencyPolicy(exceptionPolicy, {
        fetchImpl: upstreamFetch(policy, { advisoryPackage: "express" }),
      }),
      /hono: advisory GHSA-54fx-42gc-7vw4 does not name this npm package/,
    );
  });

  await t.test("non-fixing adopted version", async () => {
    await assert.rejects(
      verifyRemoteDependencyPolicy(exceptionPolicy, {
        fetchImpl: upstreamFetch(policy, { fixedVersion: "999.0.0" }),
      }),
      /hono: advisory GHSA-54fx-42gc-7vw4 first patched version 999\.0\.0 is newer than adopted/,
    );
  });

  await t.test("adopted version must be the minimum that fixes all advisories", async () => {
    const overAdoptedPolicy = structuredClone(exceptionPolicy);
    overAdoptedPolicy.packages.hono.version = "4.12.35";
    overAdoptedPolicy.advisoryExceptions[0].adoptedVersion = "4.12.35";
    await assert.rejects(
      verifyRemoteDependencyPolicy(overAdoptedPolicy, {
        fetchImpl: upstreamFetch(overAdoptedPolicy, { fixedVersion: "4.12.34" }),
      }),
      /hono: adopted 4\.12\.35 is not the minimum version that fixes all advisories \(4\.12\.34\)/,
    );
  });
});
