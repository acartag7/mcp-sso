// Machine-client resource binding and store capability checks (contracts §6.4,
// §17.2). Kept separate so machine-client.ts remains below the source line cap.

import { AuthConfigError, type AnyBridgeConfig } from "./config.ts";
import { OAuthError } from "./errors.ts";
import type {
  ClientStore, MachineClientMutationAudit, MachineClientStore,
  VersionedMachineClientRegistration,
} from "./ports/client-store.ts";
import type { ClockPort } from "./ports/clock.ts";
import { buildResourceCatalog, resolveResource } from "./resource.ts";
import type { ResolvedResource, ResourceCatalog, ResourceConfiguration } from "./resource.ts";

export interface MachineClientResourceDeps {
  config?: AnyBridgeConfig;
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
  assertConfiguredPair(deps.config, resource, scopes);
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

/** Validate the deps `resource`/`catalog` pair against the BRIDGE's configured
 *  catalog, when the caller supplies the config.
 *
 *  Without this the context builds a THROWAWAY catalog from whatever deps carry,
 *  so provisioning accepts an unconfigured resource, or one resource paired with
 *  another's scopes, or invented scopes entirely. Nothing is minted — token-time
 *  checks still reject the credential — but it fails LATE: provisioning reports
 *  success and every use of the credential then fails, with no signal at the
 *  point the mistake was made. Validate at the boundary instead.
 *
 *  Mandatory rather than opt-in: a validation nobody passes is not a validation,
 *  and every in-repo call site already has the config to hand. */
function assertConfiguredPair(
  config: AnyBridgeConfig | undefined,
  resource: string,
  scopes: readonly string[],
): void {
  if (config === undefined) {
    throw new AuthConfigError(
      "MachineClientDeps.config is required: without the bridge configuration this boundary " +
        "cannot tell whether `resource` is one this deployment serves, so provisioning would " +
        "succeed for a credential no token request can ever use",
    );
  }
  const configured = buildResourceCatalog(
    config as unknown as ResourceConfiguration,
    { allowInsecureLocalhost: config.dev?.allowInsecureLocalhost === true },
  );
  const entry = configured.entries.find((e) => e.resource === resource);
  if (entry === undefined) {
    throw new AuthConfigError(
      `MachineClientDeps.resource "${resource}" is not a configured resource of this bridge`,
    );
  }
  // Compare as SETS, not one-way. A stray scope is an invented permission; a
  // MISSING one silently narrows provisioning, so a scope the bridge really does
  // configure gets rejected and the error blames `allowedScopes` rather than the
  // deps that were actually wrong. The catalog must BE the resource's catalog.
  const owned = new Set(entry.scopeCatalog);
  const supplied = new Set(scopes);
  const stray = scopes.find((scope) => !owned.has(scope));
  if (stray !== undefined) {
    throw new AuthConfigError(
      `MachineClientDeps.catalog contains "${stray}", which is not in the scope catalog of "${resource}"`,
    );
  }
  const missing = entry.scopeCatalog.find((scope) => !supplied.has(scope));
  if (missing !== undefined) {
    throw new AuthConfigError(
      `MachineClientDeps.catalog omits "${missing}" from the scope catalog of "${resource}"; ` +
        "it must be that resource's own catalog, not a subset",
    );
  }
}
