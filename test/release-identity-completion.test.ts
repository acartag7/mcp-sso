import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { run } from "./lib/release-packed-flow.ts";

const repo = fileURLToPath(new URL("..", import.meta.url));
const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

releaseTest("RM.17 the packed root exports the claims-only flow and route-set assertion", async () => {
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-release-identity-"));
  try {
    const pack = await run("npm", ["pack", "--ignore-scripts", "--json", "--pack-destination", base], repo);
    assert.equal(pack.code, 0, `npm pack failed:\n${pack.output}`);
    const report = JSON.parse(pack.output.slice(pack.output.indexOf("["), pack.output.lastIndexOf("]") + 1)) as Array<{ filename: string }>;
    const artifact = report[0]; assert.ok(artifact);
    const modules = join(base, "consumer", "node_modules"); await mkdir(modules, { recursive: true });
    const extract = await run("tar", ["-xzf", resolve(base, artifact.filename), "-C", modules], base);
    assert.equal(extract.code, 0, extract.output);
    const rename = await run("mv", [join(modules, "package"), join(modules, "mcp-sso")], base);
    assert.equal(rename.code, 0, rename.output);
    const dependency = await run("ln", ["-s", resolve(repo, "node_modules/jose"), join(modules, "jose")], base);
    assert.equal(dependency.code, 0, dependency.output);
    const consumer = join(base, "consumer");
    await writeFile(join(consumer, "package.json"), JSON.stringify({ name: "identity-consumer", private: true, type: "module" }));
    await writeFile(join(consumer, "check.mjs"), `
import { createUpstreamRedirectFlow, assertDistinctUpstreamFlowRoutes } from "mcp-sso";
if (typeof createUpstreamRedirectFlow !== "function" || typeof assertDistinctUpstreamFlowRoutes !== "function") process.exit(1);
`);
    const loaded = await run(process.execPath, ["check.mjs"], consumer, { ...process.env, NODE_TEST_CONTEXT: undefined });
    assert.equal(loaded.code, 0, `packed root exports failed:\n${loaded.output}`);
  } finally { await rm(base, { recursive: true, force: true }); }
});
