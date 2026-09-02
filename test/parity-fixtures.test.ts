import { test } from "node:test";
import { adapterForChainMember, adaptersForChain, adaptersForFixture } from "./parity/adapters.ts";
import { loadCorpus } from "./parity/corpus.ts";
import type { LogicalState } from "./parity/types.ts";
import { runFixture } from "./parity/runner.ts";
import { assertPreStateEstablished } from "./parity/state-assertions.ts";
import type { CaptureValues } from "./parity/types.ts";

const fixtures = (await loadCorpus()).filter((fixture) => fixture.status !== "superseded");
const chained = new Set(fixtures.filter((fixture) => fixture.chain).map((fixture) => fixture.id));

for (const fixture of fixtures.filter((candidate) => !chained.has(candidate.id))) {
  for (const adapter of adaptersForFixture(fixture)) {
    test(`${fixture.id} [${adapter}]`, async () => { await runFixture(fixture, adapter); });
  }
}

const chainIds = [...new Set(fixtures.flatMap((fixture) => fixture.chain?.id ? [fixture.chain.id] : []))];
const established = new Map<string, Required<LogicalState>>();
for (const chainId of chainIds) {
  const members = fixtures.filter((fixture) => fixture.chain?.id === chainId)
    .toSorted((a, b) => a.chain!.step - b.chain!.step);
  for (const adapter of adaptersForChain(members)) {
    test(`chain ${chainId} [${adapter}]`, async () => {
      const captures: CaptureValues = new Map();
      let established: Required<LogicalState> | undefined;
      for (const fixture of members) {
        if (established) {
          assertPreStateEstablished(fixture.given.state, established, fixture.id);
        }
        established = await runFixture(fixture, adapterForChainMember(fixture, adapter), captures);
      }
    });
  }
}
