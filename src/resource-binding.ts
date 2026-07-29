// Resource-binding store capability guard (contracts §6.3, §12.2 invariant 11).
// A multi-resource bridge — and any stored-DCR bridge where prior-scope
// accumulation is possible, including singleton mode — requires the additive
// `resourceBinding: 1` capability marker so an old custom store cannot silently
// ignore the resource argument and contribute a cross-resource grant. The check
// runs at CONSTRUCTION time (Bridge + both use-cases), before any store write,
// audit event, network operation, or route registration.

import { AuthConfigError, type BridgeConfig } from "./config.ts";
import type { StorePort } from "./ports/store.ts";
import { buildResourceCatalog } from "./resource.ts";
import type { ResourceConfiguration } from "./resource.ts";

/** True when the resource-binding capability is required for this config: a
 *  multi-resource catalog OR stored-DCR mode (where findGrantedScopes can
 *  accumulate prior scopes and thus cannot tolerate a store that ignores the
 *  resource predicate). */
export function resourceBindingRequired(config: BridgeConfig): boolean {
  const catalog = buildResourceCatalog(
    config as unknown as ResourceConfiguration,
    { allowInsecureLocalhost: config.dev?.allowInsecureLocalhost === true },
  );
  return catalog.entries.length > 1 || config.dcr.mode === "stored";
}

/** Throws AuthConfigError when the marker is required but absent or not 1.
 *  Callable at construction time, before any store write or side effect. */
export function assertResourceBindingStore(config: BridgeConfig, store: StorePort): void {
  if (resourceBindingRequired(config) && store.resourceBinding !== 1) {
    throw new AuthConfigError(
      "resourceBinding 1 is required on the StorePort for multi-resource or stored-DCR mode " +
        "(a custom store cannot silently ignore the resource lineage — contracts §6.3, §12.2 invariant 11)",
    );
  }
}
