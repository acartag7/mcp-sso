import { test } from "node:test";
import { loadCorpus } from "./parity/schema.ts";
import { runFixture } from "./parity/runner.ts";
import type { AdapterKind, CaptureValues, ParityFixture } from "./parity/types.ts";

const fixtures = (await loadCorpus()).filter((fixture) => fixture.status !== "superseded");
const chained = new Set(fixtures.filter((fixture) => fixture.chain).map((fixture) => fixture.id));

for (const fixture of fixtures.filter((candidate) => !chained.has(candidate.id))) {
  for (const adapter of adaptersFor(fixture)) {
    test(`${fixture.id} [${adapter}]`, async () => runFixture(fixture, adapter));
  }
}

const chainIds = [...new Set(fixtures.flatMap((fixture) => fixture.chain?.id ? [fixture.chain.id] : []))];
for (const chainId of chainIds) {
  const members = fixtures.filter((fixture) => fixture.chain?.id === chainId)
    .toSorted((a, b) => a.chain!.step - b.chain!.step);
  const adapters: AdapterKind[] = members.every((fixture) => fixture.kind !== "fixture" || fixture.profile === "portable")
    ? ["fastify", "express", "hono"] : ["fastify"];
  for (const adapter of adapters) {
    test(`chain ${chainId} [${adapter}]`, async () => {
      const captures: CaptureValues = new Map();
      for (const fixture of members) await runFixture(fixture, adapter, captures);
    });
  }
}

function adaptersFor(fixture: ParityFixture): AdapterKind[] {
  return fixture.kind === "fixture" && fixture.profile === "portable"
    ? ["fastify", "express", "hono"] : ["fastify"];
}
