import type { AdapterKind, ParityFixture } from "./types.ts";

const ALL_ADAPTERS: readonly AdapterKind[] = ["fastify", "express", "hono"];

export function adaptersForFixture(fixture: ParityFixture): AdapterKind[] {
  return isPortableHttp(fixture) ? [...ALL_ADAPTERS] : ["fastify"];
}

export function adaptersForChain(fixtures: ParityFixture[]): AdapterKind[] {
  return fixtures.some(isPortableHttp) ? [...ALL_ADAPTERS] : ["fastify"];
}

export function adapterForChainMember(fixture: ParityFixture, adapter: AdapterKind): AdapterKind {
  return isPortableHttp(fixture) ? adapter : "fastify";
}

function isPortableHttp(fixture: ParityFixture): boolean {
  return fixture.kind === "fixture" && fixture.profile === "portable";
}
