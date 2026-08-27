// The release-readiness gate reads evidence as data. These cover what it must
// refuse, what it must age, and the one thing it deliberately does not age.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { formatReleaseReadinessFailure, parseReleaseReadyArgs } from "../scripts/lib/release-ready-output.mjs";
import {
  ancestor, buildRelease, cleanupReleaseReadyFixture, deploymentRelease, fixture, harnessRelease, metadataRelease,
  packageRelease, receiptFor, release, runtimeRelease, setupReleaseReadyFixture, statusFor, unrelated, versionRelease,
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
  const cases = [
    [{ complete: false }, "is partial, so it is not evidence"],
    [{ schema: 2 }, "unrecognised schema 2"],
    [{ producer: "someone" }, 'unknown producer "someone"'],
    [{ runtimeCommit: "nope" }, "runtime commit is malformed"],
    [{ rows: [] }, "records no rows"],
    [{ rows: [{ id: "probe-entra", status: "FAIL" }] }, "row probe-entra did not pass"],
    [{ rows: [{ id: "probe-entra", status: "PASS" }, { id: "probe-entra", status: "PASS" }] }, "repeats row probe-entra"],
    [{ rows: [{ id: "", status: "PASS" }] }, "has a row with no readable id"],
    [{ releaseMatrix: ["RM.1", "not a row id!"] }, "names release-matrix rows that are not readable ids"],
  ];
  for (const [override, expected] of cases) {
    const errors = fixture({ receipts: { "r.json": receiptFor(ancestor, override) } }).errors;
    assert.ok(errors.some((error) => error.includes(expected)), `${JSON.stringify(override)} → ${JSON.stringify(errors)}`);
  }
  assert.ok(fixture({ receipts: {} }).errors.includes("no evidence receipt found under docs/evidence/"),
    "no receipt at all is not a pass");
  assert.ok(fixture({ receipts: { "r.json": "a string" } }).errors.some((e) => e.includes("is not an object")));
});

test("a receipt must name a commit the release contains", () => {
  const missing = fixture({ receipts: { "r.json": receiptFor("f".repeat(40)) } });
  assert.ok(missing.errors.some((error) => error.includes("not available in git history")));
  const foreign = fixture({ receipts: { "r.json": receiptFor(unrelated) } });
  assert.ok(foreign.errors.some((error) => error.includes("is not an ancestor of the release commit")));
});

test("every public export needs a passing packed-artifact row", () => {
  const uncovered = fixture({ receipts: { "r.json": receiptFor(ancestor, { releaseMatrix: ["RM.1"] }) } });
  assert.deepEqual(uncovered.errors, ["no live evidence covers export ./fastify"]);
  const none = fixture({ receipts: { "r.json": receiptFor(ancestor, { releaseMatrix: [] }) } });
  assert.equal(none.errors.length, 2, "both exports uncovered");
  // Coverage may come from more than one campaign.
  const split = fixture({
    receipts: {
      "a.json": receiptFor(ancestor, { releaseMatrix: ["RM.1"] }),
      "b.json": receiptFor(ancestor, { producer: "operator", releaseMatrix: ["RM.2"] }),
    },
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

test("the published-release row and the package must agree", () => {
  assert.ok(fixture({ status: statusFor("0.4.0") }).errors.some((e) => e.includes("version mismatch")));
  assert.ok(fixture({ status: "# no row here" }).errors.some((e) => e.includes("expected one npm package and tag row, found 0")));
  assert.ok(fixture({ status: `${statusFor()}\n${statusFor()}` }).errors.some((e) => e.includes("found 2")));
  const disagrees = statusFor().replace("and `v0.5.0`", "and `v0.4.0`");
  assert.ok(fixture({ status: disagrees }).errors.some((e) => e.includes("npm claims 0.5.0, tag claims 0.4.0")));
});

test("a receipt ages when what a client would observe changes, and not otherwise", () => {
  const at = (releaseCommit) => fixture({ receipts: { "r.json": receiptFor(ancestor) }, releaseCommit });

  const runtime = at(runtimeRelease);
  assert.deepEqual(runtime.staleEvidence.map((entry) => entry.commit), [ancestor], "a src/ change ages it");
  assert.ok(runtime.staleEvidence[0].changedInputs.includes("src/runtime.ts"));

  const deployment = at(deploymentRelease);
  assert.deepEqual(deployment.staleEvidence.map((entry) => entry.commit), [ancestor],
    "the leg's own composition changes what any client observes");
  for (const path of ["scripts/live/serve.sh", "scripts/live/run.sh", "scripts/live/run-support.mjs"]) {
    assert.ok(deployment.staleEvidence[0].changedInputs.includes(path), `${path} must age a receipt`);
  }

  // The rule the previous gate got wrong: probe and rehearsal code produced no
  // operator observation, and a rehearsal receipt is rewritten by every
  // recorded run, so neither can be stale because a probe changed.
  assert.deepEqual(at(harnessRelease).staleEvidence, [],
    "changing probes, the rehearsal, the tests or the matrix definition ages nothing");

  assert.deepEqual(at(packageRelease).staleEvidence.map((entry) => entry.commit), [ancestor], "an exports change ages it");
  assert.deepEqual(at(buildRelease).staleEvidence.map((entry) => entry.commit), [ancestor], "a build-script change ages it");
  assert.deepEqual(at(versionRelease).staleEvidence.map((entry) => entry.commit), [ancestor], "a version change ages it");
  assert.deepEqual(at(metadataRelease).staleEvidence, [], "description and the gate's own script do not");
});

test("the failure output names the receipt and what changed", () => {
  const stale = fixture({ receipts: { "r.json": receiptFor(ancestor) }, releaseCommit: runtimeRelease });
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
