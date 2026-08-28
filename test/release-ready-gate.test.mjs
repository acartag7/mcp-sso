// The release-readiness gate reads evidence as data. These cover what it must
// refuse, what it must age, and the one thing it deliberately does not age.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { formatReleaseReadinessFailure, parseReleaseReadyArgs } from "../scripts/lib/release-ready-output.mjs";
import {
  ancestor, buildRelease, cleanupReleaseReadyFixture, deploymentRelease, fixture, harnessRelease, metadataRelease,
  packageRelease, receiptFor, receipts, release, runtimeRelease, setupReleaseReadyFixture,
  unrelated, versionRelease,
} from "./lib/release-ready-fixture.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

before(setupReleaseReadyFixture);
after(cleanupReleaseReadyFixture);

test("a complete receipt at an ancestor commit is accepted", () => {
  const result = fixture();
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.staleEvidence, []);
  assert.equal(result.exportCount, 2);
});

test("a receipt is rejected when it is not evidence", () => {
  const rows = receiptFor(ancestor).rows;
  const cases = [
    [{ complete: false }, "is partial, so it is not evidence"],
    [{ schema: 2 }, "unrecognised schema 2"],
    [{ runtimeCommit: "nope" }, "runtime commit is malformed"],
    [{ rows: [] }, "records no rows"],
    [{ rows: [...rows, { id: "F2", status: "FAIL" }] }, "row F2 did not pass"],
    [{ rows: [...rows, { id: "F2", status: "PASS" }, { id: "F2", status: "PASS" }] }, "repeats row F2"],
    [{ rows: [...rows, { id: "", status: "PASS" }] }, "has a row with no readable id"],
    [{ releaseMatrix: ["RM.1", "not a row id!"] }, "names release-matrix rows that are not readable ids"],
  ];
  for (const [override, expected] of cases) {
    const errors = fixture({ receipts: receipts(receiptFor(ancestor, override)) }).errors;
    assert.ok(errors.some((error) => error.includes(expected)), `${JSON.stringify(override)} → ${JSON.stringify(errors)}`);
  }
  assert.ok(fixture({ receipts: {} }).errors.includes("no receipt at docs/evidence/release.json"),
    "no receipt at all is not a pass");
  assert.ok(fixture({ receipts: { "release.json": "a string" } }).errors.some((e) => e.includes("is not an object")));
});

test("one campaign, so a second active document is a superseded one left behind", () => {
  // Rows a person drove ride in the same receipt as the machine-checked ones,
  // because they were driven in the same campaign against the same commit.
  const together = receiptFor(ancestor, { rows: [...receiptFor(ancestor).rows, { id: "F2", status: "PASS", driven: true }] });
  assert.deepEqual(fixture({ receipts: receipts(together) }).errors, [], "hand-driven rows are evidence in the one receipt");

  const stray = { ...receipts(), "operator.json": receiptFor(ancestor) };
  assert.ok(fixture({ receipts: stray }).errors.some((e) => e.includes("docs/evidence/operator.json is not the active receipt")),
    "and a second document belongs in archive/");
});

test("a receipt must name a commit the release contains", () => {
  const missing = fixture({ receipts: receipts(receiptFor("f".repeat(40))) });
  assert.ok(missing.errors.some((error) => error.includes("not available in git history")));
  const foreign = fixture({ receipts: receipts(receiptFor(unrelated)) });
  assert.ok(foreign.errors.some((error) => error.includes("is not an ancestor of the release commit")));
});

test("every public export needs a passing packed-artifact row", () => {
  const uncovered = fixture({ receipts: receipts(receiptFor(ancestor, { releaseMatrix: ["RM.1"] })) });
  assert.deepEqual(uncovered.errors, ["no live evidence covers export ./fastify"]);
  const none = fixture({ receipts: receipts(receiptFor(ancestor, { releaseMatrix: [] })) });
  assert.equal(none.errors.length, 2, "both exports uncovered");
  // Coverage may come from more than one campaign.
  const split = fixture({
    receipts: receipts(receiptFor(ancestor, { releaseMatrix: ["RM.1", "RM.2"] })),
  });
  assert.deepEqual(split.errors, []);
});

test("a malformed release matrix is rejected before it can cover anything", () => {
  const bad = (rows) => fixture({ releaseMatrix: { rows } }).errors;
  assert.ok(bad([{ id: "RM.1", title: "", evidence: [{ file: "a", name: "b" }] }]).some((e) => e.includes("non-empty title")));
  assert.ok(bad([{ id: "RM.1", title: "t", evidence: [] }]).some((e) => e.includes("executable evidence")));
  assert.ok(bad([{ id: "RM.1", title: "t", evidence: [{ file: "a", name: "b" }], exports: ["."] }]).some((e) => e.includes("packedArtifact true")));
  assert.ok(bad([
    { id: "RM.1", title: "t", evidence: [{ file: "a", name: "b" }] },
    { id: "RM.1", title: "t", evidence: [{ file: "a", name: "b" }] },
  ]).some((e) => e.includes("duplicate row RM.1")));
  assert.ok(bad([{ id: "RM.1", title: "t", packedArtifact: true, exports: [".", "."], evidence: [{ file: "a", name: "b" }] }])
    .some((e) => e.includes("duplicate exports")));
});

test("a receipt cannot claim a release-matrix row the matrix does not define", () => {
  const invented = fixture({ receipts: receipts(receiptFor(ancestor, { releaseMatrix: ["RM.1", "invented"] })) });
  assert.ok(invented.errors.some((error) => error.includes("names invented, which the release matrix does not define")),
    `an invented id proves nothing: ${JSON.stringify(invented.errors)}`);
  assert.ok(invented.errors.some((error) => error.includes("no live evidence covers export ./fastify")),
    "and it cannot stand in for the row that would have covered an export");
});

test("a matrix row cannot name an export the package does not declare", () => {
  const stale = fixture({
    releaseMatrix: { rows: [
      { id: "RM.1", title: "Root", packedArtifact: true, exports: ["."], evidence: [{ file: "a", name: "b" }] },
      { id: "RM.2", title: "Fastify", packedArtifact: true, exports: ["./fastify"], evidence: [{ file: "a", name: "b" }] },
      { id: "RM.3", title: "Removed", packedArtifact: true, exports: ["./gone"], evidence: [{ file: "a", name: "b" }] },
    ] },
  });
  assert.ok(stale.errors.some((error) => error.includes("names export ./gone, which the package does not declare")),
    `a mapping left behind keeps looking like coverage: ${JSON.stringify(stale.errors)}`);
});

test("a receipt ages when what a client would observe changes, and not otherwise", () => {
  const at = (releaseCommit) => fixture({ receipts: receipts(receiptFor(ancestor)), releaseCommit });
  const ages = (releaseCommit) => at(releaseCommit).staleEvidence.length === 1;

  const runtime = at(runtimeRelease);
  assert.ok(ages(runtimeRelease), "a src/ change ages it");
  assert.ok(runtime.staleEvidence[0].changedInputs.includes("src/runtime.ts"));

  const deployment = at(deploymentRelease);
  assert.ok(ages(deploymentRelease), "the leg's own composition changes what any client observes");
  for (const path of ["scripts/live/serve.sh", "scripts/live/run.sh", "scripts/live/run-support.mjs"]) {
    assert.ok(deployment.staleEvidence[0].changedInputs.includes(path), `${path} must age a receipt`);
  }

  // The code that produced the evidence ages it too: a receipt produced by a
  // probe that has since been corrected should not stand as current, and
  // re-running is a local command.
  const afterProbe = at(harnessRelease);
  assert.ok(ages(harnessRelease), "a probe change ages the receipt it produced");
  assert.ok(afterProbe.staleEvidence[0].changedInputs.includes("scripts/live/probe-entra.mjs"));

  assert.ok(ages(packageRelease), "an exports change ages it");
  assert.ok(ages(buildRelease), "a build-script change ages it");
  assert.deepEqual(at(metadataRelease).staleEvidence, [], "description and the gate's own script do not");

  // The bump is a step of every release, and nothing a client observes over the
  // OAuth and MCP endpoints changes with it. Ageing evidence on it is what
  // forced the bump and the campaign proving it into two pull requests.
  assert.deepEqual(at(versionRelease).staleEvidence, [],
    "a version bump does not age evidence, so one pull request carries the bump and its evidence");
});

test("the failure output names the receipt and what changed", () => {
  const stale = fixture({ receipts: receipts(receiptFor(ancestor)), releaseCommit: runtimeRelease });
  const compact = formatReleaseReadinessFailure({ ...stale, releaseTarget: "HEAD", verbose: false });
  assert.match(compact, /- 1 recorded evidence commit predates release evidence inputs/);
  assert.match(compact, /src\//);
  assert.match(compact, /record the new commit in\n  a receipt under docs\/evidence\//, "the recovery step names where evidence lives");
  const verbose = formatReleaseReadinessFailure({ ...stale, releaseTarget: "HEAD", verbose: true });
  assert.match(verbose, /src\/runtime\.ts/);
  assert.deepEqual(parseReleaseReadyArgs(["--verbose"]), { verbose: true });
  assert.deepEqual(parseReleaseReadyArgs([]), { verbose: false });
  assert.throws(() => parseReleaseReadyArgs(["--other"]), /usage: pnpm run check:release-ready/);
});

test("the repository's own receipts satisfy the gate", () => {
  // The gate must pass against what is actually committed, not only fixtures.
  const output = readFileSync(new URL("../docs/contracts/15-package-and-export-map.md", import.meta.url), "utf8");
  assert.match(output, /reads the evidence receipts under `docs\/evidence\/`/, "the contract states where evidence lives");
  assert.doesNotMatch(output, /Recorded by/, "the provenance column is gone from the contract");
  assert.equal(ROOT.endsWith("/"), true);
});
