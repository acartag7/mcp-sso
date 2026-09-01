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

function markSuperseded(fixture: ParityFixture, replacement: string): void {
  fixture.status = "superseded";
  fixture.supersededBy = replacement;
}

async function withCorpus(
  specs: FixtureSpec[],
  check: (root: string) => Promise<void>,
): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "mcp-sso-parity-chain-"));
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

async function expectTopologyError(specs: FixtureSpec[], message: string): Promise<void> {
  await withCorpus(specs, async (root) => {
    await assert.rejects(loadCorpus(root), (error: unknown) => {
      assert.ok(error instanceof FixtureRunnerError);
      assert.equal(error.message, message);
      return true;
    });
  });
}

test("loadCorpus accepts an unchained active fixture", async () => {
  const id = fixtureId("unchained-control");
  await withCorpus([{ id }], async (root) => {
    const fixtures = await loadCorpus(root);
    assert.deepEqual(fixtures.map((fixture) => fixture.id), [id]);
  });
});

test("loadCorpus accepts a valid single-step chain", async () => {
  const id = fixtureId("single-step");
  await withCorpus([{ id, mutate: (fixture) => { fixture.chain = { id: "single", step: 1 }; } }], async (root) => {
    assert.equal((await loadCorpus(root)).length, 1);
  });
});

test("loadCorpus keeps independent chain step sequences separate", async () => {
  const first = fixtureId("independent-first");
  const second = fixtureId("independent-second");
  await withCorpus([
    { id: first, mutate: (fixture) => { fixture.chain = { id: "first-chain", step: 1 }; } },
    { id: second, mutate: (fixture) => { fixture.chain = { id: "second-chain", step: 1 }; } },
  ], async (root) => {
    assert.equal((await loadCorpus(root)).length, 2);
  });
});

test("loadCorpus orders a valid three-step chain independently of file order", async () => {
  const first = fixtureId("chain-m");
  const second = fixtureId("chain-z");
  const third = fixtureId("chain-a");
  await withCorpus([
    { id: third, mutate: (fixture) => { fixture.chain = { id: "three", step: 3, previous: second }; } },
    { id: first, mutate: (fixture) => { fixture.chain = { id: "three", step: 1 }; } },
    { id: second, mutate: (fixture) => { fixture.chain = { id: "three", step: 2, previous: first }; } },
  ], async (root) => assert.equal((await loadCorpus(root)).length, 3));
});

test("loadCorpus rejects a chain with a step gap", async () => {
  const first = fixtureId("gap-first");
  const third = fixtureId("gap-third");
  await expectTopologyError([
    { id: first, mutate: (fixture) => { fixture.chain = { id: "gap", step: 1 }; } },
    { id: third, mutate: (fixture) => { fixture.chain = { id: "gap", step: 3, previous: first }; } },
  ], "gap: chain steps must be contiguous");
});

test("loadCorpus rejects duplicate chain steps", async () => {
  const first = fixtureId("duplicate-first");
  const second = fixtureId("duplicate-second");
  await expectTopologyError([
    { id: first, mutate: (fixture) => { fixture.chain = { id: "duplicate", step: 1 }; } },
    { id: second, mutate: (fixture) => { fixture.chain = { id: "duplicate", step: 1, previous: first }; } },
  ], "duplicate: chain steps must be contiguous");
});

test("loadCorpus rejects a step-one predecessor", async () => {
  const id = fixtureId("step-one-previous");
  await expectTopologyError([
    { id, mutate: (fixture) => { fixture.chain = { id: "step-one", step: 1, previous: fixtureId("later") }; } },
  ], `${id}: wrong chain predecessor`);
});

test("loadCorpus rejects a later step with no predecessor", async () => {
  const first = fixtureId("missing-first");
  const second = fixtureId("missing-second");
  await expectTopologyError([
    { id: first, mutate: (fixture) => { fixture.chain = { id: "missing", step: 1 }; } },
    { id: second, mutate: (fixture) => { fixture.chain = { id: "missing", step: 2 }; } },
  ], `${second}: wrong chain predecessor`);
});

test("loadCorpus rejects wrong and nonexistent predecessors", async () => {
  const first = fixtureId("wrong-first");
  const second = fixtureId("wrong-second");
  const unrelated = fixtureId("wrong-unrelated");
  await expectTopologyError([
    { id: first, mutate: (fixture) => { fixture.chain = { id: "wrong", step: 1 }; } },
    { id: unrelated },
    { id: second, mutate: (fixture) => { fixture.chain = { id: "wrong", step: 2, previous: unrelated }; } },
  ], `${second}: wrong chain predecessor`);
  await expectTopologyError([
    { id: first, mutate: (fixture) => { fixture.chain = { id: "wrong", step: 1 }; } },
    { id: second, mutate: (fixture) => { fixture.chain = { id: "wrong", step: 2, previous: fixtureId("wrong-missing") }; } },
  ], `${second}: wrong chain predecessor`);
});

test("loadCorpus rejects a later-step predecessor reference", async () => {
  const first = fixtureId("later-first");
  const second = fixtureId("later-second");
  const third = fixtureId("later-third");
  await expectTopologyError([
    { id: first, mutate: (fixture) => { fixture.chain = { id: "later", step: 1 }; } },
    { id: second, mutate: (fixture) => { fixture.chain = { id: "later", step: 2, previous: third }; } },
    { id: third, mutate: (fixture) => { fixture.chain = { id: "later", step: 3, previous: second }; } },
  ], `${second}: wrong chain predecessor`);
});

test("loadCorpus rejects a predecessor from a different chain", async () => {
  const first = fixtureId("different-first");
  const second = fixtureId("different-second");
  const other = fixtureId("different-other");
  await expectTopologyError([
    { id: first, mutate: (fixture) => { fixture.chain = { id: "one", step: 1 }; } },
    { id: second, mutate: (fixture) => { fixture.chain = { id: "one", step: 2, previous: other }; } },
    { id: other, mutate: (fixture) => { fixture.chain = { id: "two", step: 1 }; } },
  ], `${second}: wrong chain predecessor`);
});

test("loadCorpus rejects a runnable gap hidden by a superseded first step", async () => {
  const history = fixtureId("hidden-first");
  const active = fixtureId("hidden-second");
  await expectTopologyError([
    { id: history, mutate: (fixture) => {
      markSuperseded(fixture, active);
      fixture.chain = { id: "hidden-first", step: 1 };
    } },
    { id: active, mutate: (fixture) => {
      fixture.chain = { id: "hidden-first", step: 2, previous: history };
    } },
  ], "hidden-first: chain steps must be contiguous");
});

test("loadCorpus rejects a runnable gap hidden by a superseded middle step", async () => {
  const first = fixtureId("hidden-middle-first");
  const history = fixtureId("hidden-middle-history");
  const third = fixtureId("hidden-middle-third");
  await expectTopologyError([
    { id: first, mutate: (fixture) => { fixture.chain = { id: "hidden-middle", step: 1 }; } },
    { id: history, mutate: (fixture) => {
      markSuperseded(fixture, third);
      fixture.chain = { id: "hidden-middle", step: 2, previous: first };
    } },
    { id: third, mutate: (fixture) => {
      fixture.chain = { id: "hidden-middle", step: 3, previous: history };
    } },
  ], "hidden-middle: chain steps must be contiguous");
});

test("loadCorpus accepts an active prefix and superseded tail", async () => {
  const first = fixtureId("prefix-first");
  const second = fixtureId("prefix-second");
  const tail = fixtureId("prefix-tail");
  await withCorpus([
    { id: first, mutate: (fixture) => { fixture.chain = { id: "prefix", step: 1 }; } },
    { id: second, mutate: (fixture) => { fixture.chain = { id: "prefix", step: 2, previous: first }; } },
    { id: tail, mutate: (fixture) => {
      markSuperseded(fixture, second);
      fixture.chain = { id: "prefix", step: 3, previous: second };
    } },
  ], async (root) => {
    assert.equal((await loadCorpus(root)).length, 3);
  });
});

test("loadCorpus ignores invalid topology on superseded history", async () => {
  const history = fixtureId("ignored-history");
  const replacement = fixtureId("ignored-replacement");
  await withCorpus([
    { id: history, mutate: (fixture) => {
      markSuperseded(fixture, replacement);
      fixture.chain = { id: "ignored", step: 2 };
    } },
    { id: replacement },
  ], async (root) => assert.equal((await loadCorpus(root)).length, 2));
});
