// The enumeration this change should have started from: every failure
// condition the previous release gate made, and what happened to it.
//
// The substantive ones are listed here as behaviour, not as prose. Each row
// builds an input that must be refused and names the refusal, so deleting a
// check turns this red rather than leaving a gap for a reviewer to find. The
// conditions that were deliberately dropped are recorded in
// docs/archive/2026-08-27-release-gate-conditions.md with the reason. The
// version claim went with them: publish.yml compares the pushed tag against
// package.json, which is that property enforced against the real tag.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import * as FIXTURE from "./lib/release-ready-fixture.mjs";
import {
  ancestor, cleanupReleaseReadyFixture, fixture, receiptFor, receipts, setupReleaseReadyFixture, unrelated,
} from "./lib/release-ready-fixture.mjs";

before(setupReleaseReadyFixture);
after(cleanupReleaseReadyFixture);

/** Each entry: what the old gate refused, the input that must still be
 *  refused, and the text that names the refusal. */
const CONDITIONS = [
  ["package version is malformed",
    () => ({ packageJson: { version: "not-a-version", exports: { ".": {} } } }), "package version is malformed"],
  ["package exports is not an object",
    () => ({ packageJson: { version: "0.5.0", exports: [] } }), "package exports must be an object"],
  ["the release commit does not resolve",
    () => ({ releaseCommit: "f".repeat(40) }), "release commit is not available in git history"],
  ["a recorded runtime commit is malformed",
    () => ({ receipts: receipts(receiptFor("nope")) }), "runtime commit is malformed"],
  ["a recorded runtime commit does not resolve",
    () => ({ receipts: receipts(receiptFor("f".repeat(40))) }), "not available in git history"],
  ["a recorded runtime commit is not an ancestor of the release commit",
    () => ({ receipts: receipts(receiptFor(unrelated)) }), "is not an ancestor of the release commit"],
  ["an export has no live evidence",
    () => ({ receipts: receipts(receiptFor(ancestor, { releaseMatrix: ["RM.1"] })) }), "no live evidence covers export ./fastify"],
  ["evidence names a matrix row the matrix does not define",
    () => ({ receipts: receipts(receiptFor(ancestor, { releaseMatrix: ["RM.1", "RM.404"] })) }),
    "names RM.404, which the release matrix does not define"],
  ["a matrix row names an export the package does not declare",
    () => ({ releaseMatrix: { rows: [
      { id: "RM.1", title: "t", packedArtifact: true, exports: ["."], evidence: [{ file: "a", name: "b" }] },
      { id: "RM.2", title: "t", packedArtifact: true, exports: ["./fastify"], evidence: [{ file: "a", name: "b" }] },
      { id: "RM.3", title: "t", packedArtifact: true, exports: ["./gone"], evidence: [{ file: "a", name: "b" }] },
    ] } }), "names export ./gone, which the package does not declare"],
  ["the release matrix repeats a row id",
    () => ({ releaseMatrix: { rows: [
      { id: "RM.1", title: "t", evidence: [{ file: "a", name: "b" }] },
      { id: "RM.1", title: "t", evidence: [{ file: "a", name: "b" }] },
    ] } }), "duplicate row RM.1"],
  ["a matrix row has no title",
    () => ({ releaseMatrix: { rows: [{ id: "RM.1", title: "  ", evidence: [{ file: "a", name: "b" }] }] } }),
    "requires a non-empty title"],
  ["a matrix row's exports are not strings",
    () => ({ releaseMatrix: { rows: [{ id: "RM.1", title: "t", exports: [7], evidence: [{ file: "a", name: "b" }] }] } }),
    "requires an exports array of strings"],
  ["a matrix row repeats an export",
    () => ({ releaseMatrix: { rows: [{ id: "RM.1", title: "t", packedArtifact: true, exports: [".", "."], evidence: [{ file: "a", name: "b" }] }] } }),
    "has duplicate exports"],
  ["a matrix row claims exports without packedArtifact",
    () => ({ releaseMatrix: { rows: [{ id: "RM.1", title: "t", exports: ["."], evidence: [{ file: "a", name: "b" }] }] } }),
    "requires packedArtifact true"],
  ["a matrix row has no executable evidence",
    () => ({ releaseMatrix: { rows: [{ id: "RM.1", title: "t", evidence: [{ file: "", name: "" }] }] } }),
    "requires executable evidence with file and name"],
  ["a receipt row has a wrongly typed id",
    () => ({ receipts: receipts(receiptFor(ancestor, { rows: [...receiptFor(ancestor).rows, { id: 123, status: "PASS" }] })) }),
    "has a row with no readable id"],
  ["a receipt records a row the campaign does not define",
    () => ({ receipts: receipts(receiptFor(ancestor, { rows: [...receiptFor(ancestor).rows, { id: "F2s", status: "PASS" }] })) }),
    "records F2s, which the campaign does not define"],
  ["a receipt names no valid run time",
    () => ({ receipts: receipts(receiptFor(ancestor, { ranAt: undefined })) }), "ranAt is not an instant"],
  ["a receipt names an impossible recording time",
    () => ({ receipts: receipts(receiptFor(ancestor, { recordedAt: "2026-13-45T99:99:99Z" })) }),
    "recordedAt is not an instant"],
  ["a receipt names a day that does not exist",
    () => ({ receipts: receipts(receiptFor(ancestor, { ranAt: "2026-02-31T12:00:00.000Z" })) }),
    "ranAt is not an instant"],
  ["a machine-checked row claims to be hand-driven",
    () => ({ receipts: receipts(receiptFor(ancestor, {
      rows: receiptFor(ancestor).rows.map((row) => (row.id === "probe-google" ? { ...row, driven: true } : row)),
    })) }), "records probe-google as hand-driven, but a probe decides it"],
  ["a hand-driven row is not marked as one",
    () => ({ receipts: receipts(receiptFor(ancestor, {
      rows: receiptFor(ancestor).rows.map((row) => (row.id === "C1" ? { id: row.id, status: "PASS" } : row)),
    })) }), "records C1 without marking it hand-driven"],
  ["a receipt claims completeness while missing a hand-driven row",
    () => ({ receipts: receipts(receiptFor(ancestor, { rows: receiptFor(ancestor).rows.filter((row) => row.id !== "C1") })) }),
    "without 1 row(s) the campaign runs: C1"],
  ["a rehearsal receipt claims completeness while missing rows",
    () => ({ receipts: receipts(receiptFor(ancestor, { rows: [{ id: "release-matrix", status: "PASS" }] })) }),
    "claims to be complete without"],
  ["the release matrix is not an object with a rows array",
    () => ({ releaseMatrix: [] }), "expected an object with a rows array"],
  ["a matrix row has no RM.N id",
    () => ({ releaseMatrix: { rows: [{ id: "invented", title: "t", exports: [], evidence: [{ file: "a", name: "b" }] }] } }),
    "every row requires an RM.N id"],
  ["a matrix row omits its exports array",
    () => ({ releaseMatrix: { rows: [{ id: "RM.1", title: "t", evidence: [{ file: "a", name: "b" }] }] } }),
    "requires an exports array of strings"],
];

test("every substantive condition the previous gate refused is still refused", () => {
  const missed = [];
  for (const [name, build, expected] of CONDITIONS) {
    const { errors } = fixture(build());
    if (!errors.some((error) => error.includes(expected))) missed.push(`${name} → ${JSON.stringify(errors)}`);
  }
  assert.deepEqual(missed, [], `conditions no longer refused:\n${missed.join("\n")}`);
  assert.equal(CONDITIONS.length, 27, "the enumeration is the record; adding a check adds a row here");
});

test("evidence ages as it did, plus the correction that lets one pull request carry both", () => {
  const { deploymentRelease, harnessRelease, packageRelease, runtimeRelease, versionRelease, buildRelease, metadataRelease } = FIXTURE;
  const ages = (releaseCommit) =>
    fixture({ receipts: receipts(), releaseCommit }).staleEvidence.length > 0;

  assert.ok(ages(runtimeRelease), "a src/ change ages evidence");
  assert.ok(ages(deploymentRelease), "so does the composition of the served leg");
  assert.ok(ages(packageRelease), "so does an exports change");
  assert.ok(ages(buildRelease), "so does a build-script change");
  assert.ok(ages(harnessRelease), "so does the code that produced the evidence");
  assert.ok(!ages(metadataRelease), "package description and the gate's own script do not");
  assert.ok(!ages(versionRelease),
    "and neither does the version bump, which is what lets one pull request carry the bump and its campaign");
});

test("what was dropped is recorded, with the reason it stopped being needed", () => {
  // Reading the archive rather than trusting the commit message: what was
  // dropped has to be written down where a reader finds it, and each entry has
  // to say why the gate no longer needs it.
  const archive = readFileSync(new URL("../docs/archive/2026-08-27-release-gate-conditions.md", import.meta.url), "utf8");
  for (const dropped of [
    "canonical level-two headings", "fenced blocks", "HTML comments", "raw angle-bracket markup",
    "malformed divider", "noncanonical Markdown", "Recorded by", "evidence digest",
    "the published-release row is absent or repeated", "raw HTML block",
  ]) {
    assert.ok(archive.includes(dropped), `the archive records dropping ${dropped}`);
  }
  for (const kept of CONDITIONS.map(([name]) => name)) {
    assert.ok(archive.includes(kept), `the archive records keeping: ${kept}`);
  }
});
