import { AuthConfigError, type BridgeConfig } from "./config.ts";
import {
  STORED_DCR_GRANT_GENERATION,
  STORED_DCR_RESOURCE_BINDING,
  type AuthCodeRecord,
  type RefreshTokenRecord,
  type StorePort,
} from "./ports/store.ts";

/** Stored-DCR use-cases cannot trust a store that ignores generation or resource arguments. */
export function assertStoredDcrGenerationStore(config: BridgeConfig, store: StorePort): void {
  if (config.dcr.mode === "stored"
    && (store.storedDcrGrantGeneration !== STORED_DCR_GRANT_GENERATION
      || store.storedDcrResourceBinding !== STORED_DCR_RESOURCE_BINDING)) {
    throw new AuthConfigError(
      `dcr.mode 'stored' requires a StorePort with storedDcrGrantGeneration ${STORED_DCR_GRANT_GENERATION} and storedDcrResourceBinding ${STORED_DCR_RESOURCE_BINDING}`,
    );
  }
}

export function expectedStoredDcrGrantGeneration(
  config: BridgeConfig,
): number | undefined {
  return config.dcr.mode === "stored"
    ? STORED_DCR_GRANT_GENERATION
    : undefined;
}

export function newGrantGeneration(config: BridgeConfig): number | null {
  return expectedStoredDcrGrantGeneration(config) ?? null;
}

export function hasExpectedGrantGeneration(
  record: AuthCodeRecord | RefreshTokenRecord,
  expected: number | undefined,
): boolean {
  return expected === undefined || record.grantGeneration === expected;
}
