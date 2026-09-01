import assert from "node:assert/strict";
import { test } from "node:test";
import { adapterForChainMember, adaptersForChain, adaptersForFixture } from "./parity/adapters.ts";
import type {
  AdapterKind,
  BootFixture,
  BootGiven,
  BootThen,
  FixtureGiven,
  FixtureReceipt,
  HttpFixture,
  ParityFixture,
} from "./parity/types.ts";

const ALL_ADAPTERS: AdapterKind[] = ["fastify", "express", "hono"];
const CLOCK = "2026-01-01T00:00:00.000Z";
const SEED = "parity-adapters-seed";
const CONTRACT = {
  section: "19",
  clause: "19.10",
  quote: "repeats every portable HTTP fixture through Express and Hono",
};
const RECEIPT: FixtureReceipt = {
  implementation: "typescript",
  version: "0.0.0",
  commit: "head",
  date: "2026-01-01",
};

interface FixtureFields {
  id?: string;
  profile?: "portable" | "host";
  chain?: { id: string; step: number; previous?: string };
  status?: "draft" | "frozen" | "superseded";
}

function httpGiven(): FixtureGiven {
  return {
    config: {},
    clock: CLOCK,
    random: { seed: SEED },
    keys: { signingPrivate: "signing-private.pem" },
    state: {},
    http: [],
    identity: { checks: [] },
    rateLimit: { checks: [] },
    protectedResource: { requiredScope: null },
  };
}

function bootThen(): BootThen {
  return { boot: { outcome: "accepted" }, outbound: [] };
}

function httpFixture(fields: FixtureFields = {}): HttpFixture {
  const core = {
    id: fields.id ?? "http",
    profile: fields.profile ?? "portable",
    contract: CONTRACT,
    chain: fields.chain,
    kind: "fixture" as const,
    given: httpGiven(),
    when: { request: { method: "POST", path: "/oauth/token" } },
    then: { status: 200, outbound: [] },
  };
  const { status = "draft" } = fields;
  if (status === "frozen") return { ...core, status, receipt: RECEIPT };
  if (status === "superseded") return { ...core, status, supersededBy: "19/replacement", receipt: RECEIPT };
  return { ...core, status };
}

function bootFixture(fields: FixtureFields = {}): BootFixture {
  const core = {
    id: fields.id ?? "boot",
    profile: fields.profile ?? "portable",
    contract: CONTRACT,
    chain: fields.chain,
    kind: "boot" as const,
    given: {
      config: {},
      clock: CLOCK,
      random: { seed: SEED },
      state: {},
      http: [],
      identity: { checks: [] },
      rateLimit: { checks: [] },
      entrypoint: "createBridgeConfig",
      keys: {},
    } satisfies BootGiven,
    then: bootThen(),
  };
  const { status = "draft" } = fields;
  if (status === "frozen") return { ...core, status, receipt: RECEIPT };
  if (status === "superseded") return { ...core, status, supersededBy: "19/replacement", receipt: RECEIPT };
  return { ...core, status };
}

interface ChainMemberSpec {
  profile: "portable" | "host";
  boot?: true;
}

function chainOf(id: string, members: ChainMemberSpec[]): ParityFixture[] {
  return members.map((member, index) => {
    const step = index + 1;
    const fields: FixtureFields = {
      id: `${id}-step-${step}`,
      profile: member.profile,
      chain: {
        id,
        step,
        ...(step > 1 ? { previous: `${id}-step-${step - 1}` } : {}),
      },
    };
    return member.boot ? bootFixture(fields) : httpFixture(fields);
  });
}

const FIXTURE_TABLE: Array<{ name: string; fixture: ParityFixture; expected: AdapterKind[] }> = [
  { name: "a portable HTTP fixture runs through every adapter", fixture: httpFixture(), expected: ALL_ADAPTERS },
  { name: "a host HTTP fixture runs through Fastify only", fixture: httpFixture({ profile: "host" }), expected: ["fastify"] },
  { name: "a portable boot fixture runs through Fastify only", fixture: bootFixture(), expected: ["fastify"] },
  { name: "a host boot fixture runs through Fastify only", fixture: bootFixture({ profile: "host" }), expected: ["fastify"] },
  {
    name: "a frozen host HTTP fixture runs through Fastify only",
    fixture: httpFixture({ profile: "host", status: "frozen" }),
    expected: ["fastify"],
  },
  {
    name: "a superseded portable HTTP fixture still names every adapter",
    fixture: httpFixture({ status: "superseded" }),
    expected: ALL_ADAPTERS,
  },
  {
    name: "a frozen portable HTTP fixture runs through every adapter",
    fixture: httpFixture({ status: "frozen" }),
    expected: ALL_ADAPTERS,
  },
  {
    name: "a superseded host HTTP fixture runs through Fastify only",
    fixture: httpFixture({ profile: "host", status: "superseded" }),
    expected: ["fastify"],
  },
  {
    name: "a frozen boot fixture runs through Fastify only",
    fixture: bootFixture({ status: "frozen" }),
    expected: ["fastify"],
  },
  {
    name: "a superseded boot fixture runs through Fastify only",
    fixture: bootFixture({ status: "superseded" }),
    expected: ["fastify"],
  },
];

for (const row of FIXTURE_TABLE) {
  test(`adaptersForFixture: ${row.name}`, () => {
    assert.deepEqual(adaptersForFixture(row.fixture), row.expected);
  });
}

const CHAIN_TABLE: Array<{ name: string; chain: () => ParityFixture[]; expected: AdapterKind[] }> = [
  {
    name: "an all-portable chain runs every adapter",
    chain: () => chainOf("chain-portable", [{ profile: "portable" }, { profile: "portable" }]),
    expected: ALL_ADAPTERS,
  },
  {
    name: "an all-host chain runs Fastify only",
    chain: () => chainOf("chain-host", [{ profile: "host" }, { profile: "host" }]),
    expected: ["fastify"],
  },
  {
    name: "a mixed chain with one host member among portable members runs every adapter",
    chain: () => chainOf("chain-mixed", [{ profile: "host" }, { profile: "portable" }, { profile: "portable" }]),
    expected: ALL_ADAPTERS,
  },
  {
    name: "an all-boot chain runs Fastify only",
    chain: () => chainOf("chain-boot", [{ profile: "portable", boot: true }, { profile: "host", boot: true }]),
    expected: ["fastify"],
  },
  {
    name: "a chain mixing boot members with portable HTTP members runs every adapter",
    chain: () => chainOf("chain-boot-mixed", [{ profile: "portable", boot: true }, { profile: "portable" }]),
    expected: ALL_ADAPTERS,
  },
];

for (const row of CHAIN_TABLE) {
  test(`adaptersForChain: ${row.name}`, () => {
    assert.deepEqual(adaptersForChain(row.chain()), row.expected);
  });
}

test("an empty chain runs Fastify only", () => {
  assert.deepEqual(adaptersForChain([]), ["fastify"]);
});

test("the host member of a mixed chain does not collapse the chain to Fastify", () => {
  const chain = chainOf("chain-regression", [{ profile: "host" }, { profile: "portable" }, { profile: "portable" }]);
  const adapters = adaptersForChain(chain);
  assert.deepEqual(adapters, ALL_ADAPTERS);
  assert.notDeepEqual(adapters, ["fastify"]);
  for (const [step, adapter] of adapters.entries()) {
    const member = chain[step];
    assert.ok(member);
    assert.equal(adapterForChainMember(member, adapter), adapter);
  }
});

for (const run of ALL_ADAPTERS) {
  test(`a portable chain member runs on ${run}, the adapter of the run`, () => {
    assert.equal(adapterForChainMember(httpFixture(), run), run);
  });
  test(`a host chain member runs on Fastify during a ${run} run`, () => {
    assert.equal(adapterForChainMember(httpFixture({ profile: "host" }), run), "fastify");
  });
  test(`a boot chain member runs on Fastify during a ${run} run`, () => {
    assert.equal(adapterForChainMember(bootFixture(), run), "fastify");
    assert.equal(adapterForChainMember(bootFixture({ profile: "host" }), run), "fastify");
  });
}

test("the adapter selectors do not mutate their inputs", () => {
  const chain = chainOf("chain-immutable", [{ profile: "host" }, { profile: "portable" }]);
  const chainBefore = structuredClone(chain);
  adaptersForChain(chain);
  for (const member of chain) {
    adapterForChainMember(member, "hono");
  }
  assert.deepEqual(chain, chainBefore);
  const fixture: ParityFixture = httpFixture({ status: "frozen" });
  const fixtureBefore = structuredClone(fixture);
  adaptersForFixture(fixture);
  adapterForChainMember(fixture, "express");
  assert.deepEqual(fixture, fixtureBefore);
});
