// Machine-client resource binding and store capability checks (contracts §6.4,
// §17.2). Kept separate so machine-client.ts remains below the source line cap.

import { AuthConfigError } from "./config.ts";
import { OAuthError } from "./errors.ts";
import type {
  ClientStore, MachineClientMutationAudit, MachineClientStore,
  VersionedMachineClientRegistration,
} from "./ports/client-store.ts";
import type { ClockPort } from "./ports/clock.ts";
import { buildResourceCatalog, resolveResource } from "./resource.ts";
import type { ResolvedResource, ResourceCatalog } from "./resource.ts";

export interface MachineClientResourceDeps {
  store: ClientStore;
  resource: string;
  catalog: readonly string[];
  legacySingletonResource?: string;
}

export interface MachineClientResourceContext {
  store: MachineClientStore;
  resource: string;
  scopeCatalog: readonly string[];
  legacySingletonResource?: string;
}

/** An old custom store may implement the lifecycle method names while silently
 * discarding the new field, so the explicit capability marker is mandatory. */
export function assertMachineClientResourceStore(store: ClientStore): void {
  if (store.machineClientResourceBinding !== 1) {
    throw new AuthConfigError(
      "machineClientResourceBinding 1 is required for machine credential resource binding (contracts §6.4, §17.2)",
    );
  }
}

/** Entry guard + one-resource context construction for provisioning/lifecycle.
 * Building the pair through the canonical catalog validator proves the supplied
 * scope catalog is valid and associates the exact snapshot with this resource. */
export function machineClientResourceContext(
  deps: MachineClientResourceDeps,
): MachineClientResourceContext {
  const candidateStore = deps.store;
  assertMachineClientResourceStore(candidateStore);
  const store = requireMachineClientStore(candidateStore);
  const resource = deps.resource;
  const scopes = deps.catalog;
  const legacySingletonResource = deps.legacySingletonResource;
  if (!Array.isArray(scopes)) {
    throw new AuthConfigError("MachineClientDeps.catalog must be a scope array");
  }
  const catalog = buildResourceCatalog({
    resource,
    scopeCatalog: [...scopes],
    defaultScopes: [],
    ...(legacySingletonResource === undefined ? {} : { legacySingletonResource }),
  }, { allowInsecureLocalhost: true });
  const resolved = catalog.entries[0];
  if (resolved === undefined || resolved.resource !== resource) {
    throw new AuthConfigError("MachineClientDeps.resource must already be canonical");
  }
  return {
    store,
    resource: resolved.resource,
    scopeCatalog: resolved.scopeCatalog,
    ...(catalog.legacySingletonResource === undefined
      ? {}
      : { legacySingletonResource: catalog.legacySingletonResource }),
  };
}

/** Bound rows compare exactly. A legacy row can acquire a binding only from an
 * explicit singleton attestation; every other unbound row is invalid_client. */
export function mutationAudit(
  clock: ClockPort,
  event: MachineClientMutationAudit["event"],
  client: VersionedMachineClientRegistration,
  resource: string,
): MachineClientMutationAudit {
  return {
    occurredAt: new Date(clock.nowMs()).toISOString(),
    event,
    clientId: client.clientId,
    scopes: [...client.allowedScopes],
    resource,
  };
}

export function lifecycleMachineClientResource(
  storedResource: string | null | undefined,
  context: MachineClientResourceContext,
): string {
  if (typeof storedResource === "string") {
    if (storedResource !== context.resource) {
      throw new OAuthError("invalid_target", "Machine client is bound to a different resource");
    }
    return storedResource;
  }
  if (context.legacySingletonResource === context.resource) return context.resource;
  throw new OAuthError("invalid_client", "Machine client resource binding is missing", 401);
}

/** Select and bind the token resource only after authentication. Request errors
 * are invalid_target; unattested legacy lineage remains invalid_client. */
export function resolveMachineClientTokenResource(
  storedResource: string | null | undefined,
  catalog: ResourceCatalog,
  requestedResource: string | undefined,
): ResolvedResource {
  const only = catalog.entries.length === 1 ? catalog.entries[0] : undefined;
  const bound = typeof storedResource === "string"
    ? storedResource
    : only !== undefined && catalog.legacySingletonResource === only.resource
      ? only.resource
      : null;
  if (bound === null) {
    throw new OAuthError("invalid_client", "Machine client resource binding is missing", 401);
  }
  const selected = resolveResource(catalog, requestedResource);
  if (bound !== selected.resource) {
    throw new OAuthError("invalid_target", "Machine client is bound to a different resource");
  }
  return selected;
}

function requireMachineClientStore(store: ClientStore): MachineClientStore {
  const candidate = store as Partial<MachineClientStore>;
  if (typeof candidate.createMachineClient !== "function"
    || typeof candidate.compareAndSwapMachineClient !== "function") {
    throw new OAuthError("server_error", "MachineClientStore atomic mutations are required", 500);
  }
  return candidate as MachineClientStore;
}
