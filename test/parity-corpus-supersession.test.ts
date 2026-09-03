import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { loadCorpus } from "./parity/corpus.ts";
import { loadFixture } from "./parity/schema-json.ts";
import type { ParityFixture } from "./parity/types.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const SECTION = "08-resource-server-verifier";
const REAL_ID = `${SECTION}/8.4-duplicate-authorization-fails-closed`;
const fixtureId = (slug: string): string => `${SECTION}/8.4-${slug}`;
type FixtureMutation = (fixture: ParityFixture) => void;
interface FixtureSpec { id: string; mutate?: FixtureMutation }

async function realFixture(): Promise<ParityFixture> {
  return loadFixture(resolve(PROJECT_ROOT, "fixtures", `${REAL_ID}.json`));
}

async function withCorpus(
  specs: FixtureSpec[],
  check: (root: string) => Promise<void>,
): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "mcp-sso-parity-supersession-"));
  try {
    const base = await realFixture();
    for (const spec of specs) {
      const copy = structuredClone(base);
      copy.id = spec.id;
      spec.mutate?.(copy);
      const path = join(root, `${spec.id}.json`);
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, JSON.stringify(copy), "utf8");
    }
    await check(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function expectCorpusError(root: string, message: string): Promise<void> {
  await assert.rejects(loadCorpus(root), (error: unknown) => {
    assert.ok(error instanceof FixtureRunnerError);
    assert.equal(error.message, message);
    return true;
  });
}

async function expectCycleError(root: string, ids: string[]): Promise<void> {
  await assert.rejects(loadCorpus(root), (error: unknown) => {
    assert.ok(error instanceof FixtureRunnerError);
    assert.ok(ids.some((id) => error.message === `${id}: supersededBy chain contains a cycle`));
    return true;
  });
}

test("loadCorpus accepts a real active fixture copied into a temporary corpus", async () => {
  const activeId = fixtureId("active-real");
  await withCorpus([{ id: activeId }], async (root) => {
    const fixtures = await loadCorpus(root);
    assert.deepEqual(fixtures.map(({ id, status }) => [id, status]), [[activeId, "frozen"]]);
  });
});

test("loadCorpus accepts superseded fixture pointing to a loaded active replacement", async () => {
  const supersededId = fixtureId("superseded");
  const replacementId = fixtureId("replacement");
  await withCorpus([
    { id: supersededId, mutate: (fixture) => { fixture.status = "superseded"; fixture.supersededBy = replacementId; } },
    { id: replacementId },
  ], async (root) => {
    const fixtures = await loadCorpus(root);
    assert.deepEqual(fixtures.map(({ id, status }) => `${id}:${status}`).toSorted(), [
      `${replacementId}:frozen`, `${supersededId}:superseded`,
    ]);
  });
});

test("loadCorpus rejects a superseded fixture whose replacement is not loaded", async () => {
  const supersededId = fixtureId("missing-source");
  const replacementId = fixtureId("missing-replacement");
  await withCorpus([{
    id: supersededId,
    mutate: (fixture) => { fixture.status = "superseded"; fixture.supersededBy = replacementId; },
  }], (root) => expectCorpusError(root, `${supersededId}: supersededBy must name a loaded fixture`));
});

test("loadCorpus rejects an empty supersededBy value", async () => {
  const supersededId = fixtureId("empty-replacement");
  await withCorpus([{
    id: supersededId,
    mutate: (fixture) => { fixture.status = "superseded"; fixture.supersededBy = ""; },
  }], (root) => expectCorpusError(root, `${supersededId}: supersededBy must name a loaded fixture`));
});

test("loadCorpus rejects a superseded fixture that points to itself", async () => {
  const supersededId = fixtureId("self-reference");
  await withCorpus([{
    id: supersededId,
    mutate: (fixture) => { fixture.status = "superseded"; fixture.supersededBy = supersededId; },
  }], (root) => expectCorpusError(root, `${supersededId}: supersededBy must name a different fixture`));
});

test("loadCorpus accepts a supersession chain ending at an active fixture", async () => {
  const firstId = fixtureId("chain-a");
  const secondId = fixtureId("chain-b");
  const activeId = fixtureId("chain-c");
  await withCorpus([
    { id: firstId, mutate: (fixture) => { fixture.status = "superseded"; fixture.supersededBy = secondId; } },
    { id: secondId, mutate: (fixture) => { fixture.status = "superseded"; fixture.supersededBy = activeId; } },
    { id: activeId },
  ], async (root) => {
    const fixtures = await loadCorpus(root);
    assert.equal(fixtures.length, 3);
  });
});

test("loadCorpus rejects a two-fixture supersession cycle", async () => {
  const firstId = fixtureId("cycle-a");
  const secondId = fixtureId("cycle-b");
  await withCorpus([
    { id: firstId, mutate: (fixture) => { fixture.status = "superseded"; fixture.supersededBy = secondId; } },
    { id: secondId, mutate: (fixture) => { fixture.status = "superseded"; fixture.supersededBy = firstId; } },
  ], (root) => expectCycleError(root, [firstId, secondId]));
});

test("loadCorpus rejects a longer supersession cycle", async () => {
  const firstId = fixtureId("long-cycle-a");
  const secondId = fixtureId("long-cycle-b");
  const thirdId = fixtureId("long-cycle-c");
  await withCorpus([
    { id: firstId, mutate: (fixture) => { fixture.status = "superseded"; fixture.supersededBy = secondId; } },
    { id: secondId, mutate: (fixture) => { fixture.status = "superseded"; fixture.supersededBy = thirdId; } },
    { id: thirdId, mutate: (fixture) => { fixture.status = "superseded"; fixture.supersededBy = firstId; } },
  ], (root) => expectCycleError(root, [firstId, secondId, thirdId]));
});
