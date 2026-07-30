// Resource-lineage checks for OAuthTokenUseCase (contracts §9.4, §9.7). Factored
// to a separate module so token.ts stays under the 250-line file limit. The
// catalog is built once per use-case instance; every lineage check re-resolves a
// stored record's resource against the CURRENT catalog.

import { AuthConfigError, type AnyBridgeConfig as BridgeConfig } from "./config.ts";
import { OAuthError } from "./errors.ts";
import { assertMachineClientResourceStore } from "./machine-client-resource.ts";
import type { ResourceBindingExpectation, StorePort } from "./ports/store.ts";
import { buildResourceCatalog, resolveResource } from "./resource.ts";
import type { ResourceCatalog, ResourceConfiguration, ResolvedResource } from "./resource.ts";
import { assertStoredDcrGenerationStore } from "./stored-dcr-generation.ts";
import { assertResourceBindingStore } from "./resource-binding.ts";

export type { ResourceCatalog } from "./resource.ts";

/** Build the immutable catalog once at construction and assert the store
 *  capability in the same step (both are boot-time guards). */
export function initTokenCatalog(config: BridgeConfig, store: StorePort): ResourceCatalog {
  if (config.clientCredentials?.enabled) {
    if (config.dcr.mode !== "stored") {
      throw new AuthConfigError("clientCredentials.enabled requires dcr.mode 'stored'");
    }
    assertMachineClientResourceStore(config.dcr.store);
  }
  assertStoredDcrGenerationStore(config, store);
  assertResourceBindingStore(config, store);
  return buildResourceCatalog(
    config as unknown as ResourceConfiguration,
    { allowInsecureLocalhost: config.dev?.allowInsecureLocalhost === true },
  );
}

/** Re-resolve a consumed code/refresh record's resource against the CURRENT
 *  catalog. A present-but-removed resource is invalid_target; a missing/empty
 *  lineage is invalid_grant (error-catalog §14: "missing/malformed persisted
 *  interactive lineage is invalid_grant"). Because code consumption is
 *  single-use, a mismatched exchange has already burned the code. */
export function resolveRecordResource(
  catalog: ResourceCatalog,
  resource: string | null | undefined,
): ResolvedResource {
  if (typeof resource !== "string" || resource.length === 0) {
    throw new OAuthError("invalid_grant", "Stored grant carries no resource lineage");
  }
  return resolveResource(catalog, resource);
}

/** The rotation expectation for refresh. A singleton catalog pins the sole
 *  resource; a null pre-0.4 lineage binds to it (one entry ⇒ the null token can
 *  only be from this resource). A multi-resource catalog carries no request-side
 *  selector yet — the store copies the stored resource and the post-rotation
 *  resolveRecordResource validates it against the catalog. */
/** The resource expectation passed into `rotateRefreshToken`.
 *
 *  A multi-resource catalog MUST always produce an expectation: returning
 *  `undefined` there would tell the store "any resource is acceptable" and let an
 *  A-bound family rotate under B. The request value selects the entry (and is
 *  itself fail-closed — unknown/empty/repeated is `invalid_target`); omission
 *  resolves only for a single-entry catalog, which is also the only place legacy
 *  null lineage may bind. */
export function refreshBindingExpectation(
  catalog: ResourceCatalog,
  requested?: string,
): ResourceBindingExpectation {
  const selected = resolveResource(catalog, requested);
  return {
    resource: selected.resource,
    // A one-entry catalog is NOT sufficient: an A-to-B singleton URL replacement
    // also has one entry, and inferring B for an A-originated null row would
    // rebind it. Only the explicit legacySingletonResource attestation permits it.
    allowLegacySingletonBinding: catalog.legacyBindingPermitted,
  };
}

export function requiredStr(value: string | undefined, label: string): string {
  if (typeof value === "string" && value) return value;
  throw new OAuthError("invalid_request", `${label} is required`);
}
