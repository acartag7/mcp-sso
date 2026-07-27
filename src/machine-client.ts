// Machine-client provisioning primitives (contracts §17.2). Library functions,
// NOT endpoints: machine clients are provisioned OUT-OF-BAND, never via open
// `/oauth/register`. The `/oauth/token` client_credentials grant that CONSUMES
// these records (`exchangeClientCredentials`) composes `verifyMachineClientSecret`.
//
// Secret (§17.2): `mcs_` + base64url(32) = 256 bits. Stored as UNSALTED SHA-256
// hex only (RFC 6819 §5.1.4.1.3 salts LOW-entropy creds; a 256-bit random secret
// needs no salt, and bcrypt on the token hot path is a DoS lever). Comparison is
// constant-time. The raw secret is returned ONCE and never retrievable.

import type {
  ActiveMachineClientRegistration,
  ClientStore,
  MachineClientRegistration,
  MachineClientMutationAudit,
  MachineClientStore,
} from "./ports/client-store.ts";
import type { ClockPort } from "./ports/clock.ts";
import type { AuditPort, AuthAuditEvent } from "./ports/audit.ts";
import { OAuthError } from "./errors.ts";
import {
  epochSeconds,
  hashMachineClientSecret,
  isPositiveInteger,
  mintClientSecret,
  mintMachineClientId,
  requireActiveMachineClient,
  rotateSecrets,
  validateAllowedScopes,
  verifyPresentedHash,
} from "./machine-client-secret.ts";
export const DEFAULT_ROTATION_GRACE_SECONDS = 86_400;
export interface MachineClientDeps {
  store: MachineClientStore;
  /** `config.scopeCatalog` — allowedScopes is validated against this. */
  catalog: readonly string[];
  clock: ClockPort;
  audit: AuditPort;
}
export interface ProvisionMachineClientInput {
  name?: string;
  /** Per-client scope ceiling. Non-empty subset of `catalog`; each entry a
   *  single RFC 6749 scope token (the §17.2 ceiling is fixed here, at
   *  provisioning, so it can never be silently widened). */
  allowedScopes: string[];
  /** Optional bounded lifetime for the provisioned (first) secret. Positive
   *  integer seconds; omitted ⇒ live until rotated. */
  secretTtlSeconds?: number;
}
export interface ProvisionedMachineClient {
  /** `mcc_<random>` — also the token `sub` (§17.2). */
  clientId: string;
  /** `mcs_<base64url(32)>` — returned ONCE; never stored or logged. */
  clientSecret: string;
}

export interface RotateSecretOptions {
  /** Overlap window; defaults to DEFAULT_ROTATION_GRACE_SECONDS. */
  graceSeconds?: number;
}

export interface RotatedSecret {
  clientSecret: string;
  version: number;
}

export interface DisabledMachineClient {
  clientId: string;
  disabledAtEpoch: number;
  version: number;
}

/** Provision a machine client. Returns the secret ONCE; the stored record holds
 *  only the SHA-256 hash. `allowedScopes` is fixed as the per-client ceiling. */
export async function provisionMachineClient(
  deps: MachineClientDeps,
  input: ProvisionMachineClientInput,
): Promise<ProvisionedMachineClient> {
  try {
    const allowedScopes = validateAllowedScopes(input.allowedScopes, deps.catalog);
    if (input.name !== undefined && (typeof input.name !== "string" || input.name.length === 0)) {
      throw new OAuthError("invalid_request", "name must be a non-empty string when provided");
    }
    if (input.secretTtlSeconds !== undefined && !isPositiveInteger(input.secretTtlSeconds)) {
      throw new OAuthError("invalid_request", "secretTtlSeconds must be a positive integer (seconds)");
    }
    const now = epochSeconds(deps.clock);
    const expiresAtEpoch = input.secretTtlSeconds === undefined ? undefined : now + input.secretTtlSeconds;
    if (expiresAtEpoch !== undefined && (!Number.isSafeInteger(expiresAtEpoch) || expiresAtEpoch < 0)) {
      throw new OAuthError("invalid_request", "secretTtlSeconds produces an invalid expiry");
    }
    const clientId = mintMachineClientId();
    const clientSecret = mintClientSecret();
    const record: ActiveMachineClientRegistration = {
      clientId,
      redirectUris: [],
      applicationType: "machine",
      issuedAtEpoch: now,
      name: input.name,
      allowedScopes,
      status: "active",
      version: 1,
      secrets: [{
        hash: hashMachineClientSecret(clientSecret),
        createdAtEpoch: now,
        expiresAtEpoch,
      }],
    };
    const durableAudit = mutationAudit(deps.clock, "oauth.client.provision", record);
    if (!await deps.store.createMachineClient(record, durableAudit)) {
      throw new OAuthError("server_error", "Machine client identifier collision", 500);
    }
    await safeAudit(deps.audit, successAudit(durableAudit));
    return { clientId, clientSecret };
  } catch (error) {
    await safeAudit(deps.audit, {
      occurredAt: new Date(deps.clock.nowMs()).toISOString(),
      event: "oauth.client.provision", status: "failure",
      reason: error instanceof OAuthError ? error.code : "internal_error",
    });
    throw error;
  }
}

/** Rotate a machine client's secret: demote the live secret to a
 *  `now + graceSeconds` grace window, add the new live secret, and trim to the
 *  permitted active set (≤ 2 unexpired; one live). Returns the new secret ONCE.
 *  Unknown / non-machine / malformed-record clientId ⇒ `invalid_client` (401). */
export async function rotateMachineClientSecret(
  deps: MachineClientDeps,
  clientId: string,
  opts?: RotateSecretOptions,
): Promise<RotatedSecret> {
  try {
    const graceSeconds = opts?.graceSeconds ?? DEFAULT_ROTATION_GRACE_SECONDS;
    if (!isPositiveInteger(graceSeconds)) {
      throw new OAuthError("invalid_request", "graceSeconds must be a positive integer (seconds)");
    }
    const now = epochSeconds(deps.clock);
    const graceExpiresAtEpoch = now + graceSeconds;
    if (!Number.isSafeInteger(graceExpiresAtEpoch) || graceExpiresAtEpoch < 0) {
      throw new OAuthError("invalid_request", "graceSeconds produces an invalid expiry");
    }
    const client = requireActiveMachineClient(await deps.store.find(clientId));
    const clientSecret = mintClientSecret();
    const next: ActiveMachineClientRegistration = {
      ...client,
      version: client.version + 1,
      secrets: rotateSecrets(
        client.secrets,
        now,
        graceSeconds,
        hashMachineClientSecret(clientSecret),
      ),
    };
    const durableAudit = mutationAudit(deps.clock, "oauth.client.rotate_secret", next);
    if (!await deps.store.compareAndSwapMachineClient(client.version, next, durableAudit)) {
      throw new OAuthError("invalid_request", "Machine client changed; retry rotation", 409);
    }
    await safeAudit(deps.audit, successAudit(durableAudit));
    return { clientSecret, version: next.version };
  } catch (error) {
    await safeAudit(deps.audit, {
      occurredAt: new Date(deps.clock.nowMs()).toISOString(),
      event: "oauth.client.rotate_secret", status: "failure",
      clientId,
      reason: error instanceof OAuthError ? error.code : "internal_error",
    });
    throw error;
  }
}

/** Disable a machine client via an auditable tombstone. Stored secret digests
 *  are removed atomically with the durable audit record. */
export async function disableMachineClient(
  deps: MachineClientDeps,
  clientId: string,
): Promise<DisabledMachineClient> {
  try {
    const client = requireActiveMachineClient(await deps.store.find(clientId));
    const next: MachineClientRegistration = {
      ...client,
      status: "disabled",
      version: client.version + 1,
      secrets: [],
      disabledAtEpoch: epochSeconds(deps.clock),
    };
    const durableAudit = mutationAudit(deps.clock, "oauth.client.disable", next);
    if (!await deps.store.compareAndSwapMachineClient(client.version, next, durableAudit)) {
      throw new OAuthError("invalid_request", "Machine client changed; retry disable", 409);
    }
    await safeAudit(deps.audit, successAudit(durableAudit));
    return {
      clientId,
      disabledAtEpoch: next.disabledAtEpoch,
      version: next.version,
    };
  } catch (error) {
    await safeAudit(deps.audit, {
      occurredAt: new Date(deps.clock.nowMs()).toISOString(),
      event: "oauth.client.disable", status: "failure", clientId,
      reason: error instanceof OAuthError ? error.code : "internal_error",
    });
    throw error;
  }
}

/** Timing-safe verification primitive the §9.4 client_credentials grant (S3b)
 *  composes into client authentication. Uniform-work + fail-closed: the secret
 *  is hashed BEFORE the lookup (no client-existence oracle); every path runs the
 *  same fixed two-comparison loop (no slot/active-count signal); a missing /
 *  non-machine / malformed / >2-active (poisoned) record ⇒ `false`, never thrown. */
export async function verifyMachineClientSecret(
  deps: { store: ClientStore; clock: ClockPort },
  clientId: string,
  presentedSecret: string,
): Promise<boolean> {
  if (typeof presentedSecret !== "string" || presentedSecret.length === 0) return false;
  const presented = hashMachineClientSecret(presentedSecret);
  const client = await deps.store.find(clientId);
  return verifyPresentedHash(client, presented, epochSeconds(deps.clock));
}

function mutationAudit(
  clock: ClockPort,
  event: MachineClientMutationAudit["event"],
  client: MachineClientRegistration,
): MachineClientMutationAudit {
  return {
    occurredAt: new Date(clock.nowMs()).toISOString(),
    event,
    clientId: client.clientId,
    scopes: client.allowedScopes,
  };
}

function successAudit(audit: MachineClientMutationAudit): AuthAuditEvent {
  return { ...audit, status: "success" };
}

async function safeAudit(audit: AuditPort, event: AuthAuditEvent): Promise<void> {
  try {
    await audit.writeAuthEvent(event);
  } catch {
    // The required durable audit was committed by MachineClientStore. This
    // supplemental sink must not suppress an already-committed credential.
  }
}
export { rotateSecrets } from "./machine-client-secret.ts";
