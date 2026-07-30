// Machine-client lifecycle primitives (contracts §17.2). Library functions,
// not endpoints: provisioning, rotation, and disable happen out of band.

import type {
  ActiveMachineClientRegistration,
  ClientStore,
  MachineClientMutationAudit,
  VersionedMachineClientRegistration,
} from "./ports/client-store.ts";
import type { AnyBridgeConfig } from "./config.ts";
import type { ClockPort } from "./ports/clock.ts";
import type { AuditPort, AuthAuditEvent } from "./ports/audit.ts";
import { OAuthError } from "./errors.ts";
import {
  epochSeconds,
  hashMachineClientSecret,
  isPositiveInteger,
  mintClientSecret,
  mintMachineClientId,
  rotateSecrets,
  validateAllowedScopes,
} from "./machine-client-secret.ts";
import {
  parseMachineClientRegistration,
  type ParsedActiveMachineClientRegistration,
} from "./machine-client-record.ts";
import {
  lifecycleMachineClientResource, machineClientResourceContext, mutationAudit,
} from "./machine-client-resource.ts";

export const DEFAULT_ROTATION_GRACE_SECONDS = 86_400;
export const MAX_ROTATION_GRACE_SECONDS = 86_400;
export interface MachineClientDeps {
  /** A v0.3.0 ClientStore remains source-compatible; mutation calls require
   * the atomic MachineClientStore extension and fail closed when it is absent. */
  store: ClientStore;
  /** The scope catalog owned by `resource`; the pair is validated at entry. */
  catalog: readonly string[];
  /** Canonical resource this credential is provisioned and mutated under. */
  resource: string;
  /** Explicit singleton attestation permitting a pre-0.4 row to bind on mutation. */
  legacySingletonResource?: string;
  /** The bridge configuration. When supplied, `resource` must be one of ITS
   *  configured resources and `catalog` must be that resource's own scope
   *  catalog — otherwise provisioning would accept an unconfigured resource or
   *  invented scopes and mint a credential that fails at every use. Optional
   *  only for source compatibility with pre-0.4 callers. */
  config?: AnyBridgeConfig;
  clock: ClockPort;
  audit: AuditPort;
}

export interface ProvisionMachineClientInput {
  name?: string;
  allowedScopes: string[];
  secretTtlSeconds?: number;
}

export interface ProvisionedMachineClient {
  clientId: string;
  clientSecret: string;
}

export interface RotateSecretOptions {
  graceSeconds?: number;
}

export interface RotatedSecret {
  clientSecret: string;
}
export interface VersionedRotatedSecret extends RotatedSecret {
  version: number;
}

export interface DisabledMachineClient {
  clientId: string;
  disabledAtEpoch: number;
  version: number;
}

/** Create version 1 and its required durable audit in one store transaction. */
export async function provisionMachineClient(
  deps: MachineClientDeps,
  input: ProvisionMachineClientInput,
): Promise<ProvisionedMachineClient> {
  let clientId: string | undefined;
  try {
    const context = machineClientResourceContext(deps);
    const store = context.store;
    const allowedScopes = validateAllowedScopes(input.allowedScopes, context.scopeCatalog);
    if (input.name !== undefined && (typeof input.name !== "string" || input.name.length === 0)) {
      throw new OAuthError("invalid_request", "name must be a non-empty string when provided");
    }
    if (input.secretTtlSeconds !== undefined && !isPositiveInteger(input.secretTtlSeconds)) {
      throw new OAuthError("invalid_request", "secretTtlSeconds must be a positive integer (seconds)");
    }
    const now = epochSeconds(deps.clock);
    const ttl = input.secretTtlSeconds === undefined
      ? undefined
      : validateExpiryOffset(now, input.secretTtlSeconds, "secretTtlSeconds");
    clientId = mintMachineClientId();
    const clientSecret = mintClientSecret();
    const record: ActiveMachineClientRegistration = {
      clientId,
      redirectUris: [],
      applicationType: "machine",
      issuedAtEpoch: now,
      ...(input.name === undefined ? {} : { name: input.name }),
      allowedScopes,
      resource: context.resource,
      status: "active",
      version: 1,
      secrets: [{
        hash: hashMachineClientSecret(clientSecret),
        createdAtEpoch: now,
        ...(ttl === undefined ? {} : { expiresAtEpoch: now + ttl }),
      }],
    };
    const durableAudit = mutationAudit(deps.clock, "oauth.client.provision", record, context.resource);
    if (!await store.createMachineClient(record, durableAudit)) {
      throw new OAuthError("server_error", "Machine client identifier collision", 500);
    }
    safeAudit(deps.audit, { ...durableAudit, status: "success" });
    return { clientId, clientSecret };
  } catch (error) {
    safeAudit(deps.audit, failureAudit(deps.clock, "oauth.client.provision", error, clientId));
    throw error;
  }
}

/** Rotate with one CAS winner. A conflict never returns the minted raw secret. */
export async function rotateMachineClientSecret(
  deps: MachineClientDeps,
  clientId: string,
  opts?: RotateSecretOptions,
): Promise<VersionedRotatedSecret> {
  try {
    const context = machineClientResourceContext(deps);
    const store = context.store;
    const graceSeconds = opts?.graceSeconds ?? DEFAULT_ROTATION_GRACE_SECONDS;
    if (!isPositiveInteger(graceSeconds) || graceSeconds > MAX_ROTATION_GRACE_SECONDS) {
      throw new OAuthError("invalid_request", `graceSeconds must be an integer between 1 and ${MAX_ROTATION_GRACE_SECONDS}`);
    }
    const now = epochSeconds(deps.clock);
    validateExpiryOffset(now, graceSeconds, "graceSeconds");
    const current = requireMutableActive(
      parseMachineClientRegistration(await store.find(clientId), clientId, now),
    );
    const resource = lifecycleMachineClientResource(current.resource, context);
    const clientSecret = mintClientSecret();
    const next: ActiveMachineClientRegistration = {
      ...current,
      resource,
      version: current.version + 1,
      secrets: rotateSecrets(
        current.secrets,
        now,
        graceSeconds,
        hashMachineClientSecret(clientSecret),
      ),
    };
    const durableAudit = mutationAudit(deps.clock, "oauth.client.rotate_secret", next, resource);
    if (!await store.compareAndSwapMachineClient(current.version, next, durableAudit)) {
      throw new OAuthError("invalid_request", "Machine client changed; retry rotation", 409);
    }
    safeAudit(deps.audit, { ...durableAudit, status: "success" });
    return { clientSecret, version: next.version };
  } catch (error) {
    safeAudit(deps.audit, failureAudit(deps.clock, "oauth.client.rotate_secret", error, clientId));
    throw error;
  }
}

/** Atomically replace an active credential with a hash-free tombstone. */
export async function disableMachineClient(
  deps: MachineClientDeps,
  clientId: string,
): Promise<DisabledMachineClient> {
  try {
    const context = machineClientResourceContext(deps);
    const store = context.store;
    const now = epochSeconds(deps.clock);
    const current = requireMutableActive(
      parseMachineClientRegistration(await store.find(clientId), clientId, now),
    );
    const resource = lifecycleMachineClientResource(current.resource, context);
    const next: VersionedMachineClientRegistration = {
      ...current,
      resource,
      status: "disabled",
      version: current.version + 1,
      secrets: [],
      disabledAtEpoch: now,
    };
    const durableAudit = mutationAudit(deps.clock, "oauth.client.disable", next, resource);
    if (!await store.compareAndSwapMachineClient(current.version, next, durableAudit)) {
      throw new OAuthError("invalid_request", "Machine client changed; retry disable", 409);
    }
    safeAudit(deps.audit, { ...durableAudit, status: "success" });
    return { clientId, disabledAtEpoch: now, version: next.version };
  } catch (error) {
    safeAudit(deps.audit, failureAudit(deps.clock, "oauth.client.disable", error, clientId));
    throw error;
  }
}

function requireMutableActive(
  client: ReturnType<typeof parseMachineClientRegistration>,
): ParsedActiveMachineClientRegistration {
  if (client?.status !== "active" || client.version >= Number.MAX_SAFE_INTEGER) {
    throw new OAuthError("invalid_client", "Machine client record is invalid or inactive", 401);
  }
  return client;
}

function failureAudit(
  clock: ClockPort,
  event: MachineClientMutationAudit["event"],
  error: unknown,
  clientId?: string,
): AuthAuditEvent {
  return {
    occurredAt: new Date(clock.nowMs()).toISOString(),
    event,
    status: "failure",
    clientId,
    reason: error instanceof OAuthError ? error.code : "internal_error",
  };
}

function safeAudit(audit: AuditPort, event: AuthAuditEvent): void {
  try {
    void Promise.resolve(audit.writeAuthEvent(event)).catch(() => {});
  } catch {
    // A success already has durable store evidence; a failure committed no row.
  }
}

function validateExpiryOffset(now: number, seconds: number, field: string): number {
  const expiry = now + seconds;
  if (!Number.isSafeInteger(expiry) || expiry < 0) {
    throw new OAuthError("invalid_request", `${field} produces an invalid expiry`);
  }
  return seconds;
}

export { rotateSecrets } from "./machine-client-secret.ts";
export { verifyMachineClientSecret } from "./machine-client-auth.ts";
