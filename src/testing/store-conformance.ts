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
import { registerSubjectRows } from "./store-conformance-subjects.ts";
import type { MakeStore, StoreConformanceOptions } from "./store-conformance-fixtures.ts";

export type { MakeStore, StoreConformanceOptions } from "./store-conformance-fixtures.ts";

const SECTIONS = [
  registerLifecycleRows,
  registerGrantRows,
  registerRefreshRows,
  registerRevocationRows,
  registerSubjectRows,
  registerSweepRows,
] as const;

/** Register the whole StorePort conformance suite for one adapter.
 *
 *  `options` carries fixtures for the parts of §12 an adapter may satisfy its
 *  own way — today, starting an expiry lifecycle for a store that omits the
 *  optional `startExpiryCollection` hook. */
export function runStoreConformance(
  label: string, make: MakeStore, options: StoreConformanceOptions = {},
): void {
  for (const registerSection of SECTIONS) registerSection(label, make, options);
}
