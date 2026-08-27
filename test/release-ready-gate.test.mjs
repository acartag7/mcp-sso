import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { formatReleaseReadinessFailure, parseReleaseReadyArgs } from "../scripts/lib/release-ready-output.mjs";
import {
  ancestor, buildRelease, cleanupReleaseReadyFixture, compatibilityFor, evidenceDigestFor, evidenceRelease, fixture,
  deploymentRelease, harnessRelease, metadataRelease, modeRelease, packageRelease, release, rowDefinitionRelease,
  runtimeRelease, setupReleaseReadyFixture, statusFor, unrelated, versionRelease,
} from "./lib/release-ready-fixture.mjs";

before(setupReleaseReadyFixture);
after(cleanupReleaseReadyFixture);
test("release ready gate accepts complete evidence at an ancestor commit", () => {
  assert.deepEqual(fixture().errors, []);
});
test("release ready gate names a runtime commit outside the release history", () => {
  const result = fixture({ compatibility: compatibilityFor(unrelated) });
  assert.ok(result.errors.includes(`recorded runtime commit ${unrelated} is not an ancestor of release commit ${release}`));
});

test("release ready gate rejects runtime changes after the evidence commit", () => {
  const result = fixture({ releaseCommit: runtimeRelease });
  assert.deepEqual(result.staleEvidence, [{ commit: ancestor, changedInputs: ["src/runtime.ts"] }]);
});

test("release ready gate rejects evidence-definition changes after the evidence commit", () => {
  const result = fixture({ releaseCommit: evidenceRelease });
  const stale = result.staleEvidence.find((entry) => entry.commit === ancestor);
  assert.ok(stale);
  for (const file of [
    "examples/example.ts", "scripts/live/probe.mjs", "scripts/run-release-matrix.mjs", "test/evidence.test.ts",
    "scripts/check-release-matrix.mjs", "scripts/lib/release-matrix-outcome.mjs", "docs/verification.md",
    ".github/workflows/publish.yml", "pnpm-lock.yaml", "pnpm-workspace.yaml",
  ]) assert.ok(stale.changedInputs.includes(file));
});

test("release ready gate rejects package runtime changes after the evidence commit", () => {
  const result = fixture({ releaseCommit: packageRelease });
  assert.deepEqual(result.staleEvidence, [{ commit: ancestor, changedInputs: ["package.json:exports"] }]);
});

test("release ready gate permits descriptive metadata and its own command after the evidence commit", () => {
  assert.deepEqual(fixture({ releaseCommit: metadataRelease }).errors, []);
});

test("release ready gate rejects a package version change after the evidence commit", () => {
  const result = fixture({ releaseCommit: versionRelease });
  assert.deepEqual(result.staleEvidence, [{ commit: ancestor, changedInputs: ["package.json:version"] }]);
});

test("release ready gate rejects a build-command change after the evidence commit", () => {
  const result = fixture({ releaseCommit: buildRelease });
  assert.deepEqual(result.staleEvidence, [{ commit: ancestor, changedInputs: ["package.json:scripts"] }]);
});

test("release ready gate summarizes stale evidence and keeps changed paths behind --verbose", () => {
  const staleEvidence = [{
    commit: "d6143b3f00d1234567890abcdef1234567890abc",
    changedInputs: ["src/a.ts", "src/b.ts", "examples/server.ts", "scripts/live/probe.mjs", "package.json:version"],
  }];
  const compact = formatReleaseReadinessFailure({
    errors: ["version mismatch: package.json is 0.5.1, docs/verification-status.md is 0.5.0"],
    staleEvidence,
    releaseTarget: "HEAD",
    verbose: false,
  });
  assert.match(compact, /- 1 recorded evidence commit predates release runtime changes/);
  assert.match(compact, /d6143b3  5 changed inputs \(src\/, examples\/, scripts\/live\/, package\.json:version\)/);
  assert.doesNotMatch(compact, /src\/a\.ts/);
  assert.match(compact, /Re-run live verification against HEAD and record the new commit in\n  docs\/client-compatibility\.md\./);
  assert.match(compact, /- version mismatch: package\.json is 0\.5\.1, docs\/verification-status\.md is 0\.5\.0/);
  const detailed = formatReleaseReadinessFailure({ errors: [], staleEvidence, releaseTarget: "HEAD", verbose: true });
  assert.match(detailed, /      - src\/a\.ts/);
  assert.match(detailed, /      - package\.json:version/);
});

test("release ready gate keeps compact commit names unambiguous", () => {
  const staleEvidence = [
    { commit: "abcdef0123456789012345678901234567890123", changedInputs: ["src/a.ts"] },
    { commit: "abcdef0987654321098765432109876543210987", changedInputs: ["src/b.ts"] },
  ];
  const output = formatReleaseReadinessFailure({ errors: [], staleEvidence, releaseTarget: "HEAD", verbose: false });
  assert.match(output, /abcdef01  1 changed input \(src\/\)/);
  assert.match(output, /abcdef09  1 changed input \(src\/\)/);
});

test("release ready gate accepts no CLI argument except --verbose", () => {
  assert.deepEqual(parseReleaseReadyArgs([]), { verbose: false });
  assert.deepEqual(parseReleaseReadyArgs(["--verbose"]), { verbose: true });
  for (const args of [["--unknown"], ["--verbose", "--verbose"]]) {
    assert.throws(() => parseReleaseReadyArgs(args), /usage: pnpm run check:release-ready \[--verbose\]/);
  }
});

test("release ready gate verifies a squash evidence digest against the recorded main commit", () => {
  const compatibility = compatibilityFor(ancestor).replace(
    `Runtime commit \`${ancestor}\`.`,
    `Runtime evidence digest \`sha256:${evidenceDigestFor(ancestor)}\`, merged as \`${ancestor}\`.`,
  );
  assert.deepEqual(fixture({ compatibility }).errors, []);
});

test("release ready gate rejects a squash evidence digest that does not match the main commit", () => {
  const compatibility = compatibilityFor(ancestor).replace(
    `Runtime commit \`${ancestor}\`.`,
    `Runtime evidence digest \`sha256:${"0".repeat(64)}\`, merged as \`${ancestor}\`.`,
  );
  const result = fixture({ compatibility });
  assert.ok(result.errors.includes(
    `provider evidence: Provider / Client evidence digest does not match merge commit ${ancestor}`,
  ));
});

test("release evidence digests include executable file modes", () => {
  assert.notEqual(evidenceDigestFor(evidenceRelease), evidenceDigestFor(modeRelease));
});

test("release ready gate requires a runtime commit on every verified provider row", () => {
  const compatibility = compatibilityFor(ancestor).replace(`Runtime commit \`${ancestor}\`.`, "Receipt missing.");
  const result = fixture({ compatibility });
  assert.ok(result.errors.includes("provider evidence: Provider / Client has malformed runtime evidence receipt"));
});

test("release ready gate requires a real canonical date on every verified provider row", () => {
  for (const date of ["", "2026-02-30", "22-08-2026", " 2026-08-22 "]) {
    const compatibility = compatibilityFor(ancestor).replace("| 2026-08-22 |", `| ${date} |`);
    const result = fixture({ compatibility });
    assert.ok(result.errors.includes("provider evidence: Provider / Client has missing or malformed date"));
  }
});

test("release ready gate requires names for every provider row", () => {
  const names = ["Provider", "Client", "Flow"];
  for (const [index, label] of ["Provider", "Client", "Flow driven"].entries()) {
    const cells = [...names];
    cells[index] = "";
    const compatibility = compatibilityFor(ancestor).replace(
      "| Provider | Client | Flow | operator |",
      `| ${cells.join(" | ")} | operator |`,
    );
    const result = fixture({ compatibility });
    assert.ok(result.errors.includes(`provider evidence: row has missing or malformed ${label} cell`));
  }
});

test("release ready gate requires a stated limit for Verified with limit", () => {
  const missing = compatibilityFor(ancestor).replace("| Verified |", "| Verified with limit |");
  assert.ok(fixture({ compatibility: missing }).errors.includes(
    "provider evidence: Provider / Client has missing or malformed limitation",
  ));
  const complete = missing.replace(
    `Runtime commit \`${ancestor}\`.`,
    `Runtime commit \`${ancestor}\`. Limit: Stateless registration was not exercised.`,
  );
  assert.deepEqual(fixture({ compatibility: complete }).errors, []);
  const duplicate = complete.replace("was not exercised.", "was not exercised. Limit: Refresh was not exercised.");
  assert.ok(fixture({ compatibility: duplicate }).errors.includes(
    "provider evidence: Provider / Client has missing or malformed limitation",
  ));
});

test("release ready gate rejects limited or unrun payloads on Verified rows", () => {
  for (const payload of ["Limit: Registration was not exercised.", "Not run: Provider access was unavailable."]) {
    const compatibility = compatibilityFor(ancestor).replace(
      `Runtime commit \`${ancestor}\`.`,
      `Runtime commit \`${ancestor}\`. ${payload}`,
    );
    assert.ok(fixture({ compatibility }).errors.includes(
      "provider evidence: Provider / Client has contradictory Verified evidence",
    ));
  }
});

test("release ready gate permits a canonical Not run row without a runtime commit", () => {
  const compatibility = compatibilityFor(ancestor)
    .replace("| Verified |", "| Not run |")
    .replace("| 2026-08-22 |", "|  |")
    .replace(`Runtime commit \`${ancestor}\`.`, "Not run: Provider access was unavailable.");
  assert.deepEqual(fixture({ compatibility }).errors, []);
});

test("release ready gate rejects contradictory Not run evidence", () => {
  const dated = compatibilityFor(ancestor).replace("| Verified |", "| Not run |");
  assert.ok(fixture({ compatibility: dated }).errors.includes(
    "provider evidence: Provider / Client has malformed Not run evidence",
  ));
  const receipt = dated.replace("| 2026-08-22 |", "|  |");
  assert.ok(fixture({ compatibility: receipt }).errors.includes(
    "provider evidence: Provider / Client has malformed Not run evidence",
  ));
  for (const extra of [
    " Not run: A second reason.", " Limit: A contradictory limit.", ` Runtime commit \`${ancestor}\` was unavailable.`,
  ]) {
    const compatibility = compatibilityFor(ancestor)
      .replace("| Verified |", "| Not run |")
      .replace("| 2026-08-22 |", "|  |")
      .replace(`Runtime commit \`${ancestor}\`.`, `Not run: Provider access was unavailable.${extra}`);
    assert.ok(fixture({ compatibility }).errors.includes(
      "provider evidence: Provider / Client has malformed Not run evidence",
    ));
  }
});

test("release ready gate rejects an unknown provider status instead of treating it as unverified", () => {
  const compatibility = compatibilityFor(ancestor)
    .replace("| Verified |", "| Verifed |")
    .replace(`Runtime commit \`${ancestor}\`.`, "Receipt missing.");
  const result = fixture({ compatibility });
  assert.ok(result.errors.includes("provider evidence: Provider / Client has unknown status Verifed"));
});

test("release ready gate rejects duplicate provider evidence subjects", () => {
  const compatibility = compatibilityFor(ancestor);
  const row = compatibility.split("\n").find((line) => line.startsWith("| Provider | Client | Flow |"));
  assert.ok(row);
  const canonical = row.replace("| Provider |", "| Provider Name |");
  const contradictory = canonical.replace("| Provider Name |", "| ` Provider Name ` |")
    .replace("| Verified | 2026-08-22 |", "| Not run |  |")
    .replace(`Runtime commit \`${ancestor}\`.`, "Not run: The flow was not exercised.");
  const result = fixture({ compatibility: compatibility.replace(row, `${canonical}\n${contradictory}`) });
  assert.ok(result.errors.includes("provider evidence: duplicate row for ` Provider Name ` / Client / Flow"));
});

test("release ready gate names a public export without a live evidence row", () => {
  const result = fixture({ packageJson: { version: "0.5.0", exports: { ".": {}, "./fastify": {}, "./hono": {} } } });
  assert.ok(result.errors.includes("missing live evidence row for export ./hono"));
});

test("release ready gate names an evidence ID absent from the release matrix", () => {
  const compatibility = compatibilityFor(ancestor).replace("`RM.2`", "`RM.999`");
  const result = fixture({ compatibility });
  assert.ok(result.errors.includes("unknown live evidence ID RM.999 for export ./fastify"));
});

test("release ready gate requires executable packed-artifact release-matrix rows", () => {
  const base = {
    id: "RM.1", title: "Root flow", packedArtifact: true, exports: ["."],
    evidence: [{ file: "test/root.test.ts", name: "root flow" }],
  };
  const cases = [
    [{ ...base, title: "" }, "release matrix: RM.1 requires a non-empty title"],
    [{ ...base, evidence: [] }, "release matrix: RM.1 requires executable evidence with file and name"],
    [{ ...base, evidence: [{ file: "", name: "root flow" }] }, "release matrix: RM.1 requires executable evidence with file and name"],
    [{ ...base, packedArtifact: false }, "release matrix: RM.1 requires packedArtifact true before its exports can count"],
  ];
  for (const [row, expected] of cases) {
    const result = fixture({ releaseMatrix: { rows: [row] } });
    assert.ok(result.errors.includes(expected));
  }
});

test("release ready gate rejects an existing evidence row that does not cover the export", () => {
  const compatibility = compatibilityFor(ancestor).replace(
    `| \`./fastify\` | \`RM.2\` |`,
    `| \`./fastify\` | \`RM.1\` |`,
  );
  const result = fixture({ compatibility });
  assert.ok(result.errors.includes("live evidence ID RM.1 does not cover export ./fastify"));
});

test("release ready gate rejects a malformed evidence row beside a valid row", () => {
  const compatibility = `${compatibilityFor(ancestor)}\n| \`./fastify\` | RM.2 | not-a-commit |`;
  const result = fixture({ compatibility });
  assert.ok(result.errors.includes("export evidence: malformed table row for ./fastify"));
});

test("release ready gate does not count table-shaped rows outside the evidence table", () => {
  const row = `| \`./hono\` | \`RM.1\` | \`${ancestor}\` |`;
  const wrappers = [`<!--\n${row}\n-->`, `\`\`\`md\n${row}\n\`\`\``, `> ${row}`, row];
  for (const wrapped of wrappers) {
    const compatibility = `${compatibilityFor(ancestor)}\n\n${wrapped}`;
    const result = fixture({
      compatibility,
      packageJson: { version: "0.5.0", exports: { ".": {}, "./fastify": {}, "./hono": {} } },
    });
    assert.ok(result.errors.includes("missing live evidence row for export ./hono"));
    assert.ok(result.errors.includes("export evidence: table-shaped content outside the rendered table"));
  }
});

test("release ready gate rejects an evidence table hidden by Markdown", () => {
  const source = compatibilityFor(ancestor);
  const tableStart = "| Export | Live evidence | Runtime commit |";
  const cases = [
    source.replace(tableStart, `<!--\n${tableStart}`) + "\n-->",
    source.replace(tableStart, `\`\`\`md\n${tableStart}`) + "\n\`\`\`",
  ];
  const expected = [
    "export evidence: HTML comments are not allowed in the table section",
    "export evidence: fenced blocks are not allowed in the table section",
  ];
  for (const [index, compatibility] of cases.entries()) {
    assert.ok(fixture({ compatibility }).errors.includes(expected[index]));
  }
});

test("release ready gate rejects pipe-less tables outside the canonical table", () => {
  const status = `${statusFor()}\n\nItem | Status\n--- | ---\nnpm package and tag | mcp-sso@9.9.9 and v9.9.9`;
  assert.ok(fixture({ status }).errors.includes(
    "status version: table-shaped content outside the rendered table",
  ));
});

test("release ready gate rejects raw HTML wrappers in every evidence section", () => {
  const html = "<div>contradictory evidence</div>";
  const compatibility = compatibilityFor(ancestor);
  for (const heading of ["## Current matrix", "## Public export live evidence"]) {
    const changed = compatibility.replace(heading, `${heading}\n\n${html}`);
    const label = heading.includes("Current") ? "provider evidence" : "export evidence";
    assert.ok(fixture({ compatibility: changed }).errors.includes(
      `${label}: raw angle-bracket markup is not allowed in the table section`,
    ));
  }
  const status = statusFor().replace("## Published release", `## Published release\n\n${html}`);
  assert.ok(fixture({ status }).errors.includes(
    "status version: raw angle-bracket markup is not allowed in the table section",
  ));
});

test("release ready gate rejects repeated evidence and status sections", () => {
  const compatibility = `${compatibilityFor(ancestor)}\n\n## Public export live evidence`;
  assert.ok(fixture({ compatibility }).errors.includes(
    "export evidence: expected one canonical ## Public export live evidence section, found 2",
  ));
  const status = `${statusFor()}\n\n## Published release`;
  assert.ok(fixture({ status }).errors.includes(
    "status version: expected one canonical ## Published release section, found 2",
  ));
});

test("release ready gate rejects noncanonical level-two headings", () => {
  const variants = [
    "## Public export live evidence ##",
    " ## Public export live evidence",
    "## Public export live evidenc&#101;",
    "## Public export live **evidence**",
    "<h2>Public export live evidence</h2>",
    "Public export live evidence\n---",
  ];
  for (const variant of variants) {
    const compatibility = `${compatibilityFor(ancestor)}\n\n${variant}`;
    assert.ok(fixture({ compatibility }).errors.includes(
      "export evidence: evidence documents require canonical level-two headings",
    ));
  }
  const status = `${statusFor()}\n\n## Published releas&#101;`;
  assert.ok(fixture({ status }).errors.includes(
    "status version: evidence documents require canonical level-two headings",
  ));
});

test("release ready gate rejects Markdown that disguises provider evidence markers", () => {
  for (const marker of ["Limi&#116;:", "Limi**t:**", "Limi[t](https://example.invalid):", "Limit\\:", "Limi`t`:"]) {
    const compatibility = compatibilityFor(ancestor).replace(
      `Runtime commit \`${ancestor}\`.`,
      `Runtime commit \`${ancestor}\`. ${marker} Refresh was not exercised.`,
    );
    assert.ok(fixture({ compatibility }).errors.includes(
      "provider evidence: table rows contain noncanonical Markdown",
    ));
  }
});

test("release ready gate ignores section titles in prose and links", () => {
  const compatibility = compatibilityFor(ancestor).replace(
    "## Current matrix",
    "The `## Public export live evidence` section is also available through [Public export live evidence](#public-export-live-evidence).\n\n## Current matrix",
  );
  const status = statusFor().replace(
    "## Published release",
    "The `## Published release` table is linked as [Published release](#published-release).\n\n## Published release",
  );
  assert.deepEqual(fixture({ compatibility, status }).errors, []);
});

test("release ready gate does not count hidden or out-of-table status rows", () => {
  const base = statusFor().split("\n").filter((line) => !line.includes("npm package and tag")).join("\n");
  const row = "| npm package and tag | `mcp-sso@0.5.0` and `v0.5.0` |";
  const wrappers = [`<!--\n${row}\n-->`, `\`\`\`md\n${row}\n\`\`\``, `> ${row}`, row];
  for (const wrapped of wrappers) {
    const result = fixture({ status: `${base}\n\n${wrapped}` });
    assert.ok(result.errors.includes("status version: expected one npm package and tag row, found 0"));
    assert.ok(result.errors.includes("status version: table-shaped content outside the rendered table"));
  }
});

test("release ready gate rejects a status table hidden by Markdown", () => {
  const source = statusFor();
  const tableStart = "| Item | Status |";
  const cases = [
    source.replace(tableStart, `<!--\n${tableStart}`) + "\n-->",
    source.replace(tableStart, `\`\`\`md\n${tableStart}`) + "\n\`\`\`",
  ];
  const expected = [
    "status version: HTML comments are not allowed in the table section",
    "status version: fenced blocks are not allowed in the table section",
  ];
  for (const [index, status] of cases.entries()) {
    assert.ok(fixture({ status }).errors.includes(expected[index]));
  }
});

test("release ready gate rejects every malformed or duplicate named status row", () => {
  const malformed = `${statusFor()}\n| npm package and tag | mcp-sso@0.4.0 and v0.4.0 |`;
  assert.ok(fixture({ status: malformed }).errors.includes("status version: malformed npm package and tag row"));
  const conflicting = `${statusFor()}\n| npm package and tag | \`mcp-sso@0.4.0\` and \`v0.4.0\` |`;
  assert.ok(fixture({ status: conflicting }).errors.includes(
    "status version: expected one npm package and tag row, found 2",
  ));
  for (const label of [
    "**npm package and tag**", "npm&nbsp;package and tag", "npm package and tag ",
  ]) {
    const decorated = `${statusFor()}\n| ${label} | \`mcp-sso@9.9.9\` and \`v9.9.9\` |`;
    assert.ok(fixture({ status: decorated }).errors.includes("status version: malformed item label"));
  }
  const wrongCase = `${statusFor()}\n| NPM package and tag | \`mcp-sso@9.9.9\` and \`v9.9.9\` |`;
  assert.ok(fixture({ status: wrongCase }).errors.includes("status version: malformed npm package and tag row"));
});

test("release ready gate rejects the wrong column count on every status row", () => {
  for (const row of ["| Conformance claim |", "| Conformance claim | Current | contradictory |"]) {
    const status = statusFor().replace("| Conformance claim | Current |", row);
    assert.ok(fixture({ status }).errors.includes("status version: malformed table row"));
  }
});

test("release ready gate rejects a rendered status label with collapsed whitespace", () => {
  const status = `${statusFor()}\n| npm  package and tag | \`mcp-sso@9.9.9\` and \`v9.9.9\` |`;
  assert.ok(fixture({ status }).errors.includes("status version: malformed item label"));
});

test("release ready gate ignores the status label in prose", () => {
  const status = `${statusFor()}\n\nThe npm package and tag are published together.`;
  assert.deepEqual(fixture({ status }).errors, []);
});

test("release ready gate reports package and status versions", () => {
  const result = fixture({ packageJson: { version: "0.5.1", exports: { ".": {}, "./fastify": {} } } });
  assert.ok(result.errors.includes("version mismatch: package.json is 0.5.1, docs/verification-status.md is 0.5.0"));
});

test("publish runs release readiness with full git history and ordinary tests do not", async () => {
  const { readFile } = await import("node:fs/promises");
  const root = new URL("..", import.meta.url);
  const workflow = await readFile(new URL(".github/workflows/publish.yml", root), "utf8");
  const checklist = await readFile(new URL("docs/release-checklist.md", root), "utf8");
  const packageJson = JSON.parse(await readFile(new URL("package.json", root), "utf8"));
  assert.match(workflow, /fetch-depth: 0/);
  assert.match(workflow, /run: pnpm check:release-matrix/);
  assert.match(workflow, /run: pnpm check:release-ready/);
  assert.ok(workflow.indexOf("run: pnpm check:release-matrix") < workflow.indexOf("run: pnpm check:release-ready"));
  assert.ok(workflow.indexOf("run: pnpm check:release-ready") < workflow.indexOf("run: pnpm install --frozen-lockfile"));
  for (const marker of [
    "Merge the version-bump pull request", "git rev-parse HEAD", "pnpm run test:release",
    "Record the completed export rows", "pnpm run check:release-matrix", "pnpm run check:release-ready",
    "Commit only `docs/client-compatibility.md`", "Merge the evidence pull request",
  ]) assert.notEqual(checklist.indexOf(marker), -1, `release checklist is missing: ${marker}`);
  assert.ok(checklist.indexOf("Merge the version-bump pull request") < checklist.indexOf("pnpm run test:release"));
  assert.ok(checklist.indexOf("git rev-parse HEAD") < checklist.indexOf("pnpm run test:release"));
  assert.ok(checklist.indexOf("pnpm run test:release") < checklist.indexOf("Record the completed export rows"));
  assert.ok(checklist.indexOf("Record the completed export rows") < checklist.indexOf("pnpm run check:release-matrix"));
  assert.ok(checklist.indexOf("pnpm run check:release-matrix") < checklist.indexOf("pnpm run check:release-ready"));
  assert.ok(checklist.indexOf("Commit only `docs/client-compatibility.md`") > checklist.indexOf("pnpm run check:release-ready"));
  assert.ok(checklist.indexOf("Merge the evidence pull request") > checklist.indexOf("Commit only `docs/client-compatibility.md`"));
  assert.equal(packageJson.scripts.test.includes("check:release-ready"), false);
});

test("harness evidence and operator evidence age separately", () => {
  // A row a person drove through a real client against a served leg was not
  // produced by the harness, so a change to the probes, the rehearsal, or the
  // release-matrix definition cannot change what that row observed. A row the
  // record run renders was produced by exactly that code, and ages with it.
  const operatorAtAncestor = fixture({
    compatibility: compatibilityFor(ancestor, { exportCommit: harnessRelease }),
    releaseCommit: harnessRelease,
  });
  assert.deepEqual(operatorAtAncestor.errors, []);
  assert.deepEqual(operatorAtAncestor.staleEvidence, [], "a harness change leaves an operator row standing");

  const renderedAtAncestor = fixture({
    compatibility: compatibilityFor(ancestor, { exportCommit: harnessRelease, rendered: true }),
    releaseCommit: harnessRelease,
  });
  assert.deepEqual(renderedAtAncestor.staleEvidence.map((entry) => entry.commit), [ancestor],
    "a harness change ages the rows the record run renders");
  assert.ok(renderedAtAncestor.staleEvidence[0].changedInputs.includes("scripts/live/probe.mjs"));

  const exportsAtAncestor = fixture({
    compatibility: compatibilityFor(harnessRelease, { exportCommit: ancestor }),
    releaseCommit: harnessRelease,
  });
  assert.deepEqual(exportsAtAncestor.staleEvidence.map((entry) => entry.commit), [ancestor],
    "export rows come out of the release matrix, so they age with the harness too");

  const operatorAfterRuntime = fixture({
    compatibility: compatibilityFor(ancestor, { exportCommit: runtimeRelease }),
    releaseCommit: runtimeRelease,
  });
  assert.deepEqual(operatorAfterRuntime.staleEvidence.map((entry) => entry.commit), [ancestor],
    "a runtime change ages every row, including one an operator drove");
  assert.ok(operatorAfterRuntime.staleEvidence[0].changedInputs.includes("src/runtime.ts"));
});

test("the leg's own composition ages every row, and the row definitions age the rendered ones", () => {
  // `run.sh`, `serve.sh` and `run-support.mjs` choose the entry point, map the
  // environment onto the example's configuration, and expose the hostname. A
  // change there changes what any client observes without touching src/, so an
  // operator's observation of the old served configuration is not current.
  const operatorAfterDeployment = fixture({
    compatibility: compatibilityFor(ancestor, { exportCommit: deploymentRelease }),
    releaseCommit: deploymentRelease,
  });
  assert.deepEqual(operatorAfterDeployment.staleEvidence.map((entry) => entry.commit), [ancestor],
    "a change to the served leg ages an operator row");
  assert.ok(operatorAfterDeployment.staleEvidence[0].changedInputs.includes("scripts/live/serve.sh"));

  // The list of rows the record run renders is part of the harness, wherever
  // the file lives: a row generated under an obsolete definition is not current.
  const renderedAfterDefinition = fixture({
    compatibility: compatibilityFor(ancestor, { exportCommit: rowDefinitionRelease, rendered: true }),
    releaseCommit: rowDefinitionRelease,
  });
  assert.deepEqual(renderedAfterDefinition.staleEvidence.map((entry) => entry.commit), [ancestor],
    "the renderer's own row definitions age the rows it writes");
  assert.ok(renderedAfterDefinition.staleEvidence[0].changedInputs.includes("scripts/live/render-evidence.mjs"));

  const operatorAfterDefinition = fixture({
    compatibility: compatibilityFor(ancestor, { exportCommit: rowDefinitionRelease }),
    releaseCommit: rowDefinitionRelease,
  });
  assert.deepEqual(operatorAfterDefinition.staleEvidence, [],
    "a row an operator drove does not depend on what the renderer writes");
});

test("a Not run row cannot skip the provenance check", () => {
  // The Not run branch returns early, so the provenance check has to run before
  // it: a row that never names how it was driven must fail whatever its status.
  const notRun = compatibilityFor(ancestor).replace(
    `| Provider | Client | Flow | operator | Verified | 2026-08-22 | Runtime commit \`${ancestor}\`. |`,
    "| Provider | Client | Flow | typo | Not run |  | Not run: the provider was unavailable. |",
  );
  const result = fixture({ compatibility: notRun });
  assert.ok(result.errors.some((error) => error.includes('has unknown "Recorded by" value typo')),
    `a Not run row with unreadable provenance must fail: ${JSON.stringify(result.errors)}`);
});
