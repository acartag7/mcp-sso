import { test } from "node:test";
import { loadCorpus } from "./parity/schema.ts";
import { runFixture } from "./parity/runner.ts";
import type { CaptureValues } from "./parity/types.ts";
import { adapterForChainMember, adaptersForChain, adaptersForFixture } from "./parity/adapters.ts";

const fixtures = (await loadCorpus()).filter((fixture) => fixture.status !== "superseded");
const chained = new Set(fixtures.filter((fixture) => fixture.chain).map((fixture) => fixture.id));

for (const fixture of fixtures.filter((candidate) => !chained.has(candidate.id))) {
  for (const adapter of adaptersForFixture(fixture)) {
    test(`${fixture.id} [${adapter}]`, async () => runFixture(fixture, adapter));
  }
}

const chainIds = [...new Set(fixtures.flatMap((fixture) => fixture.chain?.id ? [fixture.chain.id] : []))];
for (const chainId of chainIds) {
  const members = fixtures.filter((fixture) => fixture.chain?.id === chainId)
    .toSorted((a, b) => a.chain!.step - b.chain!.step);
  for (const adapter of adaptersForChain(members)) {
    test(`chain ${chainId} [${adapter}]`, async () => {
      const captures: CaptureValues = new Map();
      for (const fixture of members) {
        await runFixture(fixture, adapterForChainMember(fixture, adapter), captures);
      }
    });
  }
}
