import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { loadCorpus } from "./parity/corpus.ts";
import { loadFixture } from "./parity/schema-json.ts";
import type { CaptureSpec, ParityFixture } from "./parity/types.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const SECTION = "08-resource-server-verifier";
const REAL_ID = `${SECTION}/8.4-duplicate-authorization-fails-closed`;
const fixtureId = (slug: string): string => `${SECTION}/8.4-${slug}`;
type FixtureMutation = (fixture: ParityFixture) => void;
interface FixtureSpec { id: string; mutate?: FixtureMutation }

async function realFixture(): Promise<ParityFixture> {
  return loadFixture(resolve(PROJECT_ROOT, "fixtures", `${REAL_ID}.json`));
}

function setChain(fixture: ParityFixture, id: string, step: number, previous?: string): void {
  fixture.chain = { id, step, ...(previous ? { previous } : {}) };
}

function setCaptures(fixture: ParityFixture, ...names: string[]): void {
  if (fixture.kind !== "fixture") throw new Error("capture requires an HTTP fixture");
  fixture.then.captures = names.map((name): CaptureSpec => ({ name, source: { bodyPointer: "/token" } }));
}

function makeBoot(fixture: ParityFixture): void {
  if (fixture.kind !== "fixture") throw new Error("expected an HTTP fixture");
  const { config, clock, random, keys, state, http, identity, rateLimit } = fixture.given;
  const record = fixture as unknown as Record<string, unknown>;
  record.kind = "boot";
  delete record.when;
  record.given = { entrypoint: "Bridge", config, clock, random, keys, state, http, identity, rateLimit };
  record.then = { boot: { outcome: "accepted" }, outbound: [] };
}

function markSuperseded(fixture: ParityFixture, replacement: string): void {
  fixture.status = "superseded";
  fixture.supersededBy = replacement;
}

async function withCorpus(specs: FixtureSpec[], check: (root: string) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "mcp-sso-parity-captures-"));
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

async function expectCorpusError(specs: FixtureSpec[], message: string): Promise<void> {
  await withCorpus(specs, async (root) => {
    await assert.rejects(loadCorpus(root), (error: unknown) => {
      assert.ok(error instanceof FixtureRunnerError);
      assert.equal(error.message, message);
      return true;
    });
  });
}

async function expectAccepted(specs: FixtureSpec[]): Promise<void> {
  await withCorpus(specs, async (root) => assert.equal((await loadCorpus(root)).length, specs.length));
}

test("loadCorpus rejects duplicate capture names within one runnable fixture", async () => {
  const id = fixtureId("capture-within-fixture");
  await expectCorpusError([{
    id,
    mutate: (fixture) => { setChain(fixture, "within", 1); setCaptures(fixture, "token", "token"); },
  }], "within: duplicate capture name token");
});

test("loadCorpus rejects duplicate capture names across consecutive fixtures", async () => {
  const first = fixtureId("capture-first");
  const second = fixtureId("capture-second");
  await expectCorpusError([
    { id: first, mutate: (fixture) => { setChain(fixture, "across", 1); setCaptures(fixture, "token"); } },
    { id: second, mutate: (fixture) => { setChain(fixture, "across", 2, first); setCaptures(fixture, "token"); } },
  ], "across: duplicate capture name token");
});

test("loadCorpus accepts the same capture name in different chains", async () => {
  await expectAccepted([
    { id: fixtureId("capture-chain-one"), mutate: (fixture) => { setChain(fixture, "one", 1); setCaptures(fixture, "token"); } },
    { id: fixtureId("capture-chain-two"), mutate: (fixture) => { setChain(fixture, "two", 1); setCaptures(fixture, "token"); } },
  ]);
});

test("loadCorpus accepts distinct capture names in one chain", async () => {
  const first = fixtureId("distinct-first");
  await expectAccepted([
    { id: first, mutate: (fixture) => { setChain(fixture, "distinct", 1); setCaptures(fixture, "token"); } },
    { id: fixtureId("distinct-second"), mutate: (fixture) => { setChain(fixture, "distinct", 2, first); setCaptures(fixture, "refresh"); } },
  ]);
});

test("loadCorpus accepts a boot fixture before a captured HTTP step", async () => {
  const boot = fixtureId("boot-capture-first");
  await expectAccepted([
    { id: boot, mutate: (fixture) => { makeBoot(fixture); setChain(fixture, "boot", 1); } },
    { id: fixtureId("boot-capture-second"), mutate: (fixture) => { setChain(fixture, "boot", 2, boot); setCaptures(fixture, "token"); } },
  ]);
});

test("loadCorpus does not reserve names from superseded history", async () => {
  const history = fixtureId("capture-history");
  const active = fixtureId("capture-active");
  await withCorpus([
    { id: history, mutate: (fixture) => { markSuperseded(fixture, active); setCaptures(fixture, "token"); setChain(fixture, "history", 1); } },
    { id: active, mutate: (fixture) => { setChain(fixture, "history", 1); setCaptures(fixture, "token"); } },
  ], async (root) => {
    const fixtures = await loadCorpus(root);
    assert.deepEqual(fixtures.map(({ id, status }) => [id, status]).toSorted(), [
      [active, "frozen"], [history, "superseded"],
    ]);
  });
});
