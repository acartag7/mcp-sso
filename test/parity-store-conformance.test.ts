// Runs the shared store and client-store conformance suites against the fixture
// store, so the parity runner's store is held to the same invariants in §12 the
// shipped adapters are. The legacy-subject rows seed rows the way a fixture's
// `given.state` can: past every `StorePort` boundary, straight into the tables.

import { STORED_DCR_GRANT_GENERATION, type StorePort } from "../src/ports/store.ts";
import { runClientStoreConformance } from "../src/testing/client-store-conformance.ts";
import { runStoreConformance } from "../src/testing/store-conformance.ts";
import type { LegacySubjectFixture, LegacySubjectState } from "../src/testing/store-conformance-fixtures.ts";
import type { LogicalTables, RefreshFamily, StoredRefresh } from "./parity/logical-state.ts";
import { SeededRandom } from "./parity/random.ts";
import { FixtureStore } from "./parity/store.ts";

function fixtureTables(store: StorePort): LogicalTables {
  return (store as unknown as { tables: LogicalTables }).tables;
}

function seedFixtureLegacy(store: StorePort, fixture: LegacySubjectFixture): void {
  const tables = fixtureTables(store);
  tables.authCodes.set(fixture.authCode.codeHash, { ...fixture.authCode, grantGeneration: STORED_DCR_GRANT_GENERATION });
  tables.families.set(fixture.refreshToken.familyId, {
    resource: fixture.refreshToken.resource, grantGeneration: STORED_DCR_GRANT_GENERATION,
  } satisfies RefreshFamily);
  tables.refreshTokens.set(fixture.refreshToken.tokenHash, {
    ...fixture.refreshToken, grantGeneration: STORED_DCR_GRANT_GENERATION,
  } satisfies StoredRefresh);
}

function inspectFixtureLegacy(store: StorePort, fixture: LegacySubjectFixture): LegacySubjectState {
  const tables = fixtureTables(store);
  return {
    authCodeExists: tables.authCodes.has(fixture.authCode.codeHash),
    predecessorConsumed: tables.refreshTokens.get(fixture.refreshToken.tokenHash)?.consumedAt != null,
    familyRevoked: tables.families.get(fixture.refreshToken.familyId)?.revokedAt != null,
    successorExists: tables.refreshTokens.has(fixture.successorHash),
  };
}

runStoreConformance("fixture store", () =>
  new FixtureStore({}, new SeededRandom("fixture-store-conformance")), {
  seedLegacySubjectRows: seedFixtureLegacy, inspectLegacySubjectRows: inspectFixtureLegacy,
});

runClientStoreConformance("fixture store", () =>
  new FixtureStore({}, new SeededRandom("fixture-client-store-conformance")));
