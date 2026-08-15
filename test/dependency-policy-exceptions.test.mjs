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
  makeTransitiveException,
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

test("a transitive advisory exception binds to a single lockfile resolution", async (t) => {
  await t.test("recorded exception with a matching resolution passes", async () => {
    const root = await fixture();
    await makeTransitiveException(root);
    await verifyLocalDependencyPolicy(root, NOW);
  });

  await t.test("adopted version drift from the lockfile resolution", async () => {
    const root = await fixture();
    await makeTransitiveException(root, { version: "3.1.6", lockfileVersion: "3.1.5" });
    await assert.rejects(
      verifyLocalDependencyPolicy(root, NOW),
      /fast-uri: adopted version 3\.1\.6 != lockfile resolution 3\.1\.5/,
    );
  });

  await t.test("two resolved versions reject", async () => {
    const root = await fixture();
    await makeTransitiveException(root, { secondVersion: "3.0.0" });
    await assert.rejects(
      verifyLocalDependencyPolicy(root, NOW),
      /fast-uri: lockfile resolves 2 versions; a transitive exception requires exactly one/,
    );
  });

  await t.test("duplicate records for one package reject", async () => {
    const root = await fixture();
    const policy = await loadDependencyPolicy(root);
    const original = policy.advisoryExceptions.find((record) => record.package === "hono");
    const duplicate = {
      ...original,
      advisoryIds: ["GHSA-79qm-7rj5-m7r9"],
      justification: "Must not be accepted: a second record for an excepted package.",
    };
    await replace(
      join(root, "docs/dependency-ledger.md"),
      '"advisoryExceptions": [',
      `"advisoryExceptions": [\n    ${JSON.stringify(duplicate, null, 2).replaceAll("\n", "\n    ")},`,
    );
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /hono: duplicate advisory exception/);
  });

  await t.test("package absent from the lockfile", async () => {
    const root = await fixture();
    await makeTransitiveException(root, { packageName: "left-pad" });
    await assert.rejects(
      verifyLocalDependencyPolicy(root, NOW),
      /left-pad: transitive advisory exception package is missing from the lockfile/,
    );
  });

  await t.test("directly pinned package must use the direct kind", async () => {
    const root = await fixture();
    await makeTransitiveException(root, { packageName: "express" });
    await assert.rejects(
      verifyLocalDependencyPolicy(root, NOW),
      /express: transitive advisory exception must not name a directly pinned package/,
    );
  });

  await t.test("missing kind is rejected", async () => {
    const root = await fixture();
    await makeHonoExceptionYoung(root);
    await replace(
      join(root, "docs/dependency-ledger.md"),
      '"kind": "direct",\n      "package": "hono",',
      '"package": "hono",',
    );
    await assert.rejects(verifyLocalDependencyPolicy(root, NOW), /kind must be "direct" or "transitive"/);
  });

  await t.test("an alias-resolved second version cannot hide from the parser", async (t) => {
    await t.test("bare alias key", async () => {
      const root = await fixture();
      await makeTransitiveException(root);
      await replace(
        join(root, "pnpm-lock.yaml"),
        "  fast-uri@3.1.5: {}",
        "  'evil-alias@npm:fast-uri@3.1.2': {}",
      );
      await assert.rejects(
        verifyLocalDependencyPolicy(root, NOW),
        /unsupported package entry: 'evil-alias@npm:fast-uri@3\.1\.2'/,
      );
    });

    await t.test("alias key carrying an inline mapping", async () => {
      const root = await fixture();
      await makeTransitiveException(root);
      await replace(
        join(root, "pnpm-lock.yaml"),
        "  fast-uri@3.1.5:\n",
        "  'evil-alias@npm:fast-uri@3.1.2': {resolution: {integrity: sha512-x}}\n",
      );
      await assert.rejects(
        verifyLocalDependencyPolicy(root, NOW),
        /unsupported package entry: 'evil-alias@npm:fast-uri@3\.1\.2'/,
      );
    });
  });
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
      kind: "direct",
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
  extraVulnerabilities = [],
} = {}) {
  return async (input) => {
    const url = String(input);
    if (url.includes("api.github.com/advisories")) {
      const parsed = new URL(url);
      const advisoryId = parsed.pathname.startsWith("/advisories/")
        ? decodeURIComponent(parsed.pathname.slice("/advisories/".length))
        : parsed.searchParams.get("cve_id");
      assert.ok(advisoryId, `advisory ID present: ${url}`);
      const transitive = Object.entries(policy.transitivePins)
        .find(([, record]) => record.advisoryIds.includes(advisoryId));
      if (transitive) {
        const [packageName, record] = transitive;
        return Response.json({
          ghsa_id: advisoryId.startsWith("GHSA-") ? advisoryId : null,
          cve_id: advisoryId.startsWith("CVE-") ? advisoryId : null,
          vulnerabilities: [{
            package: { ecosystem: "npm", name: packageName },
            first_patched_version: record.version,
          }],
        });
      }
      return Response.json({
        ghsa_id: advisoryId.startsWith("GHSA-") ? advisoryId : "GHSA-54fx-42gc-7vw4",
        cve_id: advisoryId.startsWith("CVE-") ? advisoryId : null,
        vulnerabilities: [{
          package: { ecosystem: "npm", name: advisoryPackage },
          first_patched_version: fixedVersions[advisoryId] ?? fixedVersion,
        }, ...extraVulnerabilities],
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
    const record = policy.packages[name] ?? policy.transitivePins[name];
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
        fetchImpl: upstreamFetch(policy, { fixedVersion: "4.12.99" }),
      }),
      /hono: advisory GHSA-54fx-42gc-7vw4 first patched version 4\.12\.99 is newer than adopted/,
    );
  });

  await t.test("malformed matching release evidence rejects before line filtering", async () => {
    await assert.rejects(
      verifyRemoteDependencyPolicy(exceptionPolicy, {
        fetchImpl: upstreamFetch(policy, {
          extraVulnerabilities: [{
            package: { ecosystem: "npm", name: "hono" },
            first_patched_version: null,
          }],
        }),
      }),
      /hono: advisory .* has no stable first patched version for the adopted pin/,
    );
  });

  await t.test("malformed evidence for another package does not poison the adopted package", async () => {
    await verifyRemoteDependencyPolicy(exceptionPolicy, {
      fetchImpl: upstreamFetch(policy, {
        extraVulnerabilities: [{
          package: { ecosystem: "npm", name: "express" },
          first_patched_version: null,
        }],
      }),
    });
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
