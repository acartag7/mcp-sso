// RM.16 — the shipped conformance suite, exercised the way a downstream adapter
// must: from the packed artifact, through the package's own export map. §12 and
// the threat model's release gate require every downstream store adapter to pass
// this suite, so the suite being importable from the published package is a
// release property, not a source-tree property.
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { run } from "./lib/release-packed-flow.ts";

const repo = fileURLToPath(new URL("..", import.meta.url));
const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

releaseTest("RM.16 a downstream adapter runs the shipped conformance suite from the packed artifact", async () => {
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-release-conformance-"));
  try {
    const pack = await run("npm", ["pack", "--ignore-scripts", "--json", "--pack-destination", base], repo);
    assert.equal(pack.code, 0, `npm pack failed:\n${pack.output}`);
    const start = pack.output.indexOf("[");
    const packed = JSON.parse(pack.output.slice(start, pack.output.lastIndexOf("]") + 1)) as
      Array<{ filename: string }>;
    const artifact = packed[0];
    assert.ok(artifact, `npm pack reported no artifact:\n${pack.output}`);
    const filename = artifact.filename;

    // Extract the tarball as the consumer's dependency instead of installing
    // from a registry: this proves the artifact's own export map resolves, and
    // keeps the row offline and independent of dependency resolution.
    const modules = join(base, "consumer", "node_modules");
    await mkdir(modules, { recursive: true });
    const extract = await run("tar", ["-xzf", resolve(base, filename), "-C", modules], base);
    assert.equal(extract.code, 0, `extracting the artifact failed:\n${extract.output}`);
    const rename = await run("mv", [join(modules, "package"), join(modules, "mcp-sso")], base);
    assert.equal(rename.code, 0, `naming the extracted package failed:\n${rename.output}`);

    const consumer = join(base, "consumer");
    await writeFile(join(consumer, "package.json"),
      JSON.stringify({ name: "downstream-adapter", private: true, type: "module" }, null, 2));
    await writeFile(join(consumer, "adapter.test.mjs"), `
import { runStoreConformance } from "mcp-sso/testing/store-conformance";
import { runClientStoreConformance } from "mcp-sso/testing/client-store-conformance";
import { createMemoryStore } from "mcp-sso/store/memory";
import { openSqliteStore } from "mcp-sso/store/sqlite";

runStoreConformance("DownstreamStore", () => createMemoryStore());
runClientStoreConformance("DownstreamClientStore", () => openSqliteStore(":memory:"));
`);

    const childEnv = { ...process.env };
    delete childEnv.NODE_TEST_CONTEXT;
    const suite = await run(process.execPath, ["--test", "--test-reporter=tap", "adapter.test.mjs"], consumer, childEnv);
    assert.equal(suite.code, 0, `the shipped suite did not pass from the artifact:\n${suite.output}`);
    const pass = /^# pass (\d+)$/m.exec(suite.output)?.[1];
    const fail = /^# fail (\d+)$/m.exec(suite.output)?.[1];
    assert.equal(fail, "0", `shipped suite rows failed:\n${suite.output}`);
    assert.ok(Number(pass) >= 30,
      `the shipped suite must run its rows, not resolve to an empty module (pass=${pass})`);
    // The sections are not part of the public surface; a deep import must fail.
    await writeFile(join(consumer, "deep.mjs"),
      'import "mcp-sso/testing/store-conformance-grants";\n');
    const deep = await run(process.execPath, ["deep.mjs"], consumer, childEnv);
    assert.notEqual(deep.code, 0, "a section must not be importable on its own");
    assert.match(deep.output, /ERR_PACKAGE_PATH_NOT_EXPORTED/,
      `expected the exports map to refuse the deep import:\n${deep.output}`);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});
