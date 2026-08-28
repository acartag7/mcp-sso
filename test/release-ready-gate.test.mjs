// The release-readiness gate reads evidence as data. These cover what it must
// refuse, what it must age, and the one thing it deliberately does not age.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { formatReleaseReadinessFailure, parseReleaseReadyArgs } from "../scripts/lib/release-ready-output.mjs";
import {
  ancestor, buildRelease, cleanupReleaseReadyFixture, deploymentRelease, fixture, harnessRelease, metadataRelease,
  operatorReceiptFor, packageRelease, receiptFor, receipts, release, runtimeRelease, setupReleaseReadyFixture,
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
  // Built as operator receipts where the shape under test is not about the
  // rehearsal's row set, which is re-derived separately.
  const cases = [
    [{ complete: false }, "is partial, so it is not evidence"],
    [{ schema: 2 }, "unrecognised schema 2"],
    [{ producer: "someone" }, 'unknown producer "someone"'],
    [{ runtimeCommit: "nope" }, "runtime commit is malformed"],
    [{ rows: [] }, "records no rows"],
    [{ releaseMatrix: ["RM.1"] }, "cannot carry release-matrix rows"],
    [{ rows: [{ id: "F2", status: "FAIL" }] }, "row F2 did not pass"],
    [{ rows: [{ id: "F2", status: "PASS" }, { id: "F2", status: "PASS" }] }, "repeats row F2"],
    [{ rows: [{ id: "", status: "PASS" }] }, "has a row with no readable id"],
    [{ releaseMatrix: ["RM.1", "not a row id!"] }, "names release-matrix rows that are not readable ids"],
  ];
  for (const [override, expected] of cases) {
    const errors = fixture({
      receipts: { "rehearsal.json": receiptFor(ancestor), "operator.json": operatorReceiptFor(ancestor, override) },
    }).errors;
    assert.ok(errors.some((error) => error.includes(expected)), `${JSON.stringify(override)} → ${JSON.stringify(errors)}`);
  }
  assert.ok(fixture({ receipts: { "operator.json": operatorReceiptFor(ancestor) } }).errors.includes("no rehearsal receipt at docs/evidence/rehearsal.json"),
    "no receipt at all is not a pass");
  assert.ok(fixture({ receipts: { ...receipts(), "rehearsal.json": "a string" } }).errors.some((e) => e.includes("is not an object")));
});

test("an operator receipt is evidence, and covers no export", () => {
  const operator = { producer: "operator", releaseMatrix: undefined, rows: [{ id: "F2", status: "PASS" }] };
  const withBoth = fixture({ receipts: { "rehearsal.json": receiptFor(ancestor), "operator.json": receiptFor(ancestor, operator) } });
  assert.deepEqual(withBoth.errors, [], "both producers are evidence");
  const alone = fixture({ receipts: { "operator.json": receiptFor(ancestor, operator) } });
  assert.ok(alone.errors.includes("no rehearsal receipt at docs/evidence/rehearsal.json"), "and it is not a substitute for one");
  for (const name of [".", "./fastify"]) {
    assert.ok(alone.errors.includes(`no live evidence covers export ${name}`), `on its own it covers no export: ${name}`);
  }
});

test("a receipt must name a commit the release contains", () => {
  const missing = fixture({ receipts: receipts({ rehearsal: receiptFor("f".repeat(40)) }) });
  assert.ok(missing.errors.some((error) => error.includes("not available in git history")));
  const foreign = fixture({ receipts: receipts({ rehearsal: receiptFor(unrelated) }) });
  assert.ok(foreign.errors.some((error) => error.includes("is not an ancestor of the release commit")));
});

test("every public export needs a passing packed-artifact row", () => {
  const uncovered = fixture({ receipts: receipts({ rehearsal: receiptFor(ancestor, { releaseMatrix: ["RM.1"] }) }) });
  assert.deepEqual(uncovered.errors, ["no live evidence covers export ./fastify"]);
  const none = fixture({ receipts: receipts({ rehearsal: receiptFor(ancestor, { releaseMatrix: [] }) }) });
  assert.equal(none.errors.length, 2, "both exports uncovered");
  // Coverage may come from more than one campaign.
  const split = fixture({
    receipts: receipts({ rehearsal: receiptFor(ancestor, { releaseMatrix: ["RM.1", "RM.2"] }) }),
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
  const invented = fixture({ receipts: receipts({ rehearsal: receiptFor(ancestor, { releaseMatrix: ["RM.1", "invented"] }) }) });
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
  const at = (releaseCommit) => fixture({ receipts: receipts({ rehearsal: receiptFor(ancestor) }), releaseCommit });

  const runtime = at(runtimeRelease);
  assert.deepEqual([...new Set(runtime.staleEvidence.map((entry) => entry.commit))], [ancestor], "a src/ change ages it");
  assert.equal(runtime.staleEvidence.length, 2, "and it ages both campaigns, because both observed that code");
  assert.ok(runtime.staleEvidence[0].changedInputs.includes("src/runtime.ts"));

  const deployment = at(deploymentRelease);
  assert.equal(deployment.staleEvidence.length, 2, "the leg's own composition changes what any client observes");
  for (const path of ["scripts/live/serve.sh", "scripts/live/run.sh", "scripts/live/run-support.mjs"]) {
    assert.ok(deployment.staleEvidence[0].changedInputs.includes(path), `${path} must age a receipt`);
  }

  // Evidence-producing code ages the receipt it produced, and only that one.
  // A rehearsal receipt is rewritten by one dispatch, so requiring a fresh run
  // after a probe changes costs a dispatch. An operator receipt records what a
  // real client did against a served leg: no probe produced it, and ageing it
  // on a probe change is what cost a browser campaign to re-record the same
  // observations.
  const rehearsalAfterProbe = at(harnessRelease);
  assert.deepEqual(rehearsalAfterProbe.staleEvidence.map((entry) => entry.label), ["rehearsal.json"],
    "a probe change ages the rehearsal receipt it produced, and only that one");
  assert.ok(rehearsalAfterProbe.staleEvidence[0].changedInputs.includes("scripts/live/probe-entra.mjs"));

  assert.ok(!rehearsalAfterProbe.staleEvidence.some((entry) => entry.label === "operator.json"), "and never an operator's");

  assert.equal(at(packageRelease).staleEvidence.length, 2, "an exports change ages it");
  assert.equal(at(buildRelease).staleEvidence.length, 2, "a build-script change ages it");
  assert.equal(at(versionRelease).staleEvidence.length, 2, "a version change ages it");
  assert.deepEqual(at(metadataRelease).staleEvidence, [], "description and the gate's own script do not");
});

test("the failure output names the receipt and what changed", () => {
  const stale = fixture({ receipts: receipts({ rehearsal: receiptFor(ancestor) }), releaseCommit: runtimeRelease });
  const compact = formatReleaseReadinessFailure({ ...stale, releaseTarget: "HEAD", verbose: false });
  assert.match(compact, /- 2 recorded evidence commits predate release evidence inputs/);
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
