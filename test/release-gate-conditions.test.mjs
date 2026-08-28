// The enumeration this change should have started from: every failure
// condition the previous release gate made, and what happened to it.
//
// The substantive ones are listed here as behaviour, not as prose. Each row
// builds an input that must be refused and names the refusal, so deleting a
// check turns this red rather than leaving a gap for a reviewer to find. The
// conditions that were deliberately dropped, all of them markdown shape, are
// recorded in docs/archive/2026-08-27-release-gate-conditions.md with the
// reason; nothing here should pass for them, because nothing parses prose.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import * as FIXTURE from "./lib/release-ready-fixture.mjs";
import {
  ancestor, cleanupReleaseReadyFixture, fixture, operatorReceiptFor, receiptFor, receipts, setupReleaseReadyFixture,
  statusFor, unrelated,
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
    () => ({ receipts: receipts({ rehearsal: receiptFor("nope") }) }), "runtime commit is malformed"],
  ["a recorded runtime commit does not resolve",
    () => ({ receipts: receipts({ rehearsal: receiptFor("f".repeat(40)) }) }), "not available in git history"],
  ["a recorded runtime commit is not an ancestor of the release commit",
    () => ({ receipts: receipts({ rehearsal: receiptFor(unrelated) }) }), "is not an ancestor of the release commit"],
  ["an export has no live evidence",
    () => ({ receipts: receipts({ rehearsal: receiptFor(ancestor, { releaseMatrix: ["RM.1"] }) }) }), "no live evidence covers export ./fastify"],
  ["evidence names a matrix row the matrix does not define",
    () => ({ receipts: receipts({ rehearsal: receiptFor(ancestor, { releaseMatrix: ["RM.1", "RM.404"] }) }) }),
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
  ["the published-release row is absent",
    () => ({ status: "# Status\n\n## Published release\n\n| Item | Status |\n| --- | --- |\n| other | none |" }),
    "expected one npm package and tag row"],
  ["the published-release row disagrees with itself",
    () => ({ status: statusFor().replace("and `v0.5.0`", "and `v0.4.0`") }), "npm claims 0.5.0, tag claims 0.4.0"],
  ["the published-release row disagrees with the package",
    () => ({ status: statusFor("0.4.0") }), "version mismatch: package.json is 0.5.0"],
  ["the status section appears more than once",
    () => ({ status: `${statusFor()}\n\n## Published release ##\n\n| Item | Status |\n| --- | --- |\n| npm package and tag | \`mcp-sso@9.9.9\` and \`v9.9.9\` |` }),
    "expected one npm package and tag row, found 2"],
  ["a rehearsal receipt records a row the rehearsal does not define",
    () => ({ receipts: receipts({ rehearsal: receiptFor(ancestor, { rows: [...receiptFor(ancestor).rows, { id: "invented-proof", status: "PASS" }] }) }) }),
    "row(s) the rehearsal does not define"],
  ["a rehearsal receipt claims completeness while missing rows",
    () => ({ receipts: receipts({ rehearsal: receiptFor(ancestor, { rows: [{ id: "release-matrix", status: "PASS" }] }) }) }),
    "claims to be complete without"],
  ["a second status section indented within what Markdown still renders",
    () => ({ status: `${statusFor()}\n\n   ## Published release\n\n   | Item | Status |\n   | --- | --- |\n   | npm package and tag | \`mcp-sso@9.9.9\` and \`v9.9.9\` |` }),
    "expected one npm package and tag row, found 2"],
  ["a table hidden after a fence line that does not close it",
    () => ({ status: `# Status\n\n## Published release\n\n\`\`\`\n\`\`\`not-a-closer\n\n| Item | Status |\n| --- | --- |\n| npm package and tag | \`mcp-sso@0.5.0\` and \`v0.5.0\` |` }),
    "expected one npm package and tag row, found 0"],
  ["a second status section is written as a blockquote",
    () => ({ status: `${statusFor()}\n\n> ## Published release\n>\n> | Item | Status |\n> | --- | --- |\n> | npm package and tag | \`mcp-sso@9.9.9\` and \`v9.9.9\` |` }),
    "expected one npm package and tag row, found 2"],
  ["the release matrix is not an object with a rows array",
    () => ({ releaseMatrix: [] }), "expected an object with a rows array"],
  ["a matrix row has no RM.N id",
    () => ({ releaseMatrix: { rows: [{ id: "invented", title: "t", exports: [], evidence: [{ file: "a", name: "b" }] }] } }),
    "every row requires an RM.N id"],
  ["a matrix row omits its exports array",
    () => ({ releaseMatrix: { rows: [{ id: "RM.1", title: "t", evidence: [{ file: "a", name: "b" }] }] } }),
    "requires an exports array of strings"],
  ["the published-release row is repeated",
    () => ({ status: `${statusFor()}\n| npm package and tag | \`mcp-sso@0.5.0\` and \`v0.5.0\` |` }),
    "expected one npm package and tag row, found 2"],
  ["a second version claim written anywhere in the document",
    () => ({ status: `${statusFor()}\n\nprose\n\n| npm package and tag | \`mcp-sso@9.9.9\` and \`v9.9.9\` |` }),
    "expected one npm package and tag row, found 2"],
  ["a second version claim under a Setext heading",
    () => ({ status: `${statusFor()}\n\nDifferent release\n---\n\n| npm package and tag | \`mcp-sso@9.9.9\` and \`v9.9.9\` |` }),
    "expected one npm package and tag row, found 2"],
];

test("every substantive condition the previous gate refused is still refused", () => {
  const missed = [];
  for (const [name, build, expected] of CONDITIONS) {
    const { errors } = fixture(build());
    if (!errors.some((error) => error.includes(expected))) missed.push(`${name} → ${JSON.stringify(errors)}`);
  }
  assert.deepEqual(missed, [], `conditions no longer refused:\n${missed.join("\n")}`);
  assert.equal(CONDITIONS.length, 30, "the enumeration is the record; adding a check adds a row here");
});

test("evidence ages exactly as the previous gate aged it, plus the one correction", () => {
  // The old gate aged every recorded row on runtime, deployment, package and
  // harness inputs alike. That is kept for everything except one case, which
  // is the correction this change exists to make.
  const { deploymentRelease, harnessRelease, packageRelease, runtimeRelease, versionRelease, buildRelease, metadataRelease } = FIXTURE;
  const ages = (releaseCommit, which = "rehearsal") =>
    fixture({ receipts: receipts(), releaseCommit }).staleEvidence.some((entry) => entry.label.startsWith(which));

  assert.ok(ages(runtimeRelease), "a src/ change ages evidence");
  assert.ok(ages(deploymentRelease), "so does the composition of the served leg");
  assert.ok(ages(packageRelease), "so does an exports change");
  assert.ok(ages(versionRelease), "so does a version change");
  assert.ok(ages(buildRelease), "so does a build-script change");
  assert.ok(!ages(metadataRelease), "package description and the gate's own script do not");
  assert.ok(ages(harnessRelease), "probe and rehearsal changes age the rehearsal receipt they produced");
  assert.ok(!ages(harnessRelease, "operator"),
    "and not an operator receipt, which is the correction: no probe produced what a real client did");
});

test("indentation Markdown treats as code is left alone", () => {
  // Four spaces is a code block, so a heading written that way is not a
  // rendered heading and must not count as a second section.
  const asCode = `${statusFor()}\n\n    ## Published release\n\n    | npm package and tag | \`mcp-sso@9.9.9\` and \`v9.9.9\` |`;
  assert.deepEqual(fixture({ status: asCode }).errors, [], "a code block is not a second claim");
});

test("what was dropped is recorded, and every dropped condition is a rule about Markdown", () => {
  // Reading the archive rather than trusting the commit message: what was
  // dropped has to be written down where a reader finds it, and each entry has
  // to say why a rule about Markdown stopped being needed.
  const archive = readFileSync(new URL("../docs/archive/2026-08-27-release-gate-conditions.md", import.meta.url), "utf8");
  for (const dropped of [
    "canonical level-two headings", "fenced blocks", "HTML comments", "raw angle-bracket markup",
    "malformed divider", "noncanonical Markdown", "Recorded by", "evidence digest",
  ]) {
    assert.ok(archive.includes(dropped), `the archive records dropping ${dropped}`);
  }
  for (const kept of CONDITIONS.map(([name]) => name)) {
    assert.ok(archive.includes(kept), `the archive records keeping: ${kept}`);
  }
});
