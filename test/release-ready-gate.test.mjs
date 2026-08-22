import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import {
  ancestor, buildRelease, cleanupReleaseReadyFixture, compatibilityFor, evidenceRelease, fixture, metadataRelease,
  packageRelease, release, runtimeRelease, setupReleaseReadyFixture, squashSource, statusFor, unrelated, versionRelease,
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
  assert.ok(result.errors.includes(
    `recorded runtime commit ${ancestor} predates release runtime changes: src/runtime.ts`,
  ));
});

test("release ready gate rejects evidence-definition changes after the evidence commit", () => {
  const result = fixture({ releaseCommit: evidenceRelease });
  const error = result.errors.find((message) => message.startsWith(`recorded runtime commit ${ancestor} predates`));
  assert.ok(error);
  for (const file of [
    "examples/example.ts", "scripts/live/probe.mjs", "scripts/run-release-matrix.mjs", "test/evidence.test.ts",
    ".github/workflows/publish.yml", "pnpm-lock.yaml", "pnpm-workspace.yaml",
  ]) assert.match(error, new RegExp(file.replaceAll(".", "\\.")));
});

test("release ready gate rejects package runtime changes after the evidence commit", () => {
  const result = fixture({ releaseCommit: packageRelease });
  assert.ok(result.errors.includes(
    `recorded runtime commit ${ancestor} predates release runtime changes: package.json:exports`,
  ));
});

test("release ready gate permits descriptive metadata and its own command after the evidence commit", () => {
  assert.deepEqual(fixture({ releaseCommit: metadataRelease }).errors, []);
});

test("release ready gate rejects a package version change after the evidence commit", () => {
  const result = fixture({ releaseCommit: versionRelease });
  assert.ok(result.errors.includes(
    `recorded runtime commit ${ancestor} predates release runtime changes: package.json:version`,
  ));
});

test("release ready gate rejects a build-command change after the evidence commit", () => {
  const result = fixture({ releaseCommit: buildRelease });
  assert.ok(result.errors.includes(
    `recorded runtime commit ${ancestor} predates release runtime changes: package.json:scripts`,
  ));
});

test("release ready gate checks the recorded main commit for a squash-merged live tree", () => {
  const compatibility = compatibilityFor(ancestor).replace(
    `Runtime commit \`${ancestor}\`.`,
    `Runtime commit \`${squashSource}\`, later merged without runtime changes as \`${ancestor}\`.`,
  );
  assert.deepEqual(fixture({ compatibility }).errors, []);
});

test("release ready gate rejects a runtime-different pre-squash provider commit", () => {
  const compatibility = compatibilityFor(ancestor).replace(
    `Runtime commit \`${ancestor}\`.`,
    `Runtime commit \`${unrelated}\`, later merged without runtime changes as \`${ancestor}\`.`,
  );
  const result = fixture({ compatibility });
  assert.ok(result.errors.includes(
    `provider evidence: Provider / Client runtime commit ${unrelated} differs from merge commit ${ancestor}: package.json (unreadable)`,
  ));
});

test("release ready gate requires a runtime commit on every verified provider row", () => {
  const compatibility = compatibilityFor(ancestor).replace(`Runtime commit \`${ancestor}\`.`, "Receipt missing.");
  const result = fixture({ compatibility });
  assert.ok(result.errors.includes("provider evidence: Provider / Client has malformed runtime commit receipt"));
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
      "| Provider | Client | Flow | Verified |",
      `| ${cells.join(" | ")} | Verified |`,
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
  for (const extra of [" Not run: A second reason.", " Limit: A contradictory limit."]) {
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

test("release ready gate names a public export without a live evidence row", () => {
  const result = fixture({ packageJson: { version: "0.5.0", exports: { ".": {}, "./fastify": {}, "./hono": {} } } });
  assert.ok(result.errors.includes("missing live evidence row for export ./hono"));
});

test("release ready gate names an evidence ID absent from the release matrix", () => {
  const compatibility = compatibilityFor(ancestor).replace("`RM.2`", "`RM.999`");
  const result = fixture({ compatibility });
  assert.ok(result.errors.includes("unknown live evidence ID RM.999 for export ./fastify"));
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
    assert.ok(result.errors.includes("export evidence: table-shaped row outside the rendered table"));
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

test("release ready gate rejects repeated evidence and status sections", () => {
  for (const suffix of ["", " ", " ##"]) {
    const compatibility = `${compatibilityFor(ancestor)}\n\n## Public export live evidence${suffix}`;
    assert.ok(fixture({ compatibility }).errors.includes(
      "export evidence: expected one canonical ## Public export live evidence section, found 2",
    ));
    const status = `${statusFor()}\n\n## Published release${suffix}`;
    assert.ok(fixture({ status }).errors.includes(
      "status version: expected one canonical ## Published release section, found 2",
    ));
  }
});

test("release ready gate does not count hidden or out-of-table status rows", () => {
  const base = statusFor().split("\n").filter((line) => !line.includes("npm package and tag")).join("\n");
  const row = "| npm package and tag | `mcp-sso@0.5.0` and `v0.5.0` |";
  const wrappers = [`<!--\n${row}\n-->`, `\`\`\`md\n${row}\n\`\`\``, `> ${row}`, row];
  for (const wrapped of wrappers) {
    const result = fixture({ status: `${base}\n\n${wrapped}` });
    assert.ok(result.errors.includes("status version: expected one npm package and tag row, found 0"));
    assert.ok(result.errors.includes("status version: table-shaped row outside the rendered table"));
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
  const packageJson = JSON.parse(await readFile(new URL("package.json", root), "utf8"));
  assert.match(workflow, /fetch-depth: 0/);
  assert.match(workflow, /run: pnpm check:release-ready/);
  assert.ok(workflow.indexOf("run: pnpm check:release-ready") < workflow.indexOf("run: pnpm install --frozen-lockfile"));
  assert.equal(packageJson.scripts.test.includes("check:release-ready"), false);
});
