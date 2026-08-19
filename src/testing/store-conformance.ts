// Shared StorePort conformance suite (contracts §12). MemoryStore, SqliteStore,
// MysqlStore, and any downstream SQL adapter are validated against the SAME
// invariants by calling `runStoreConformance` once per adapter. It only
// registers tests when called, so importing it has no side effects.
//
// The suite is split into sections purely for readability; `SECTIONS` is the
// whole contract and `runStoreConformance` runs all of it. A downstream adapter
// must not call a section directly — passing part of the suite is not passing
// the suite. `test/store-conformance-sections.test.ts` fails if a section
// module exists that this list does not run.
import { registerGrantRows } from "./store-conformance-grants.ts";
import { registerLifecycleRows } from "./store-conformance-lifecycle.ts";
import { registerRefreshRows } from "./store-conformance-refresh.ts";
import { registerRevocationRows } from "./store-conformance-revocation.ts";
import { registerSweepRows } from "./store-conformance-sweep.ts";
import type { MakeStore } from "./store-conformance-fixtures.ts";

export type { MakeStore } from "./store-conformance-fixtures.ts";

const SECTIONS = [
  registerLifecycleRows,
  registerGrantRows,
  registerRefreshRows,
  registerRevocationRows,
  registerSweepRows,
] as const;

/** Register the whole StorePort conformance suite for one adapter. */
export function runStoreConformance(label: string, make: MakeStore): void {
  for (const registerSection of SECTIONS) registerSection(label, make);
}
