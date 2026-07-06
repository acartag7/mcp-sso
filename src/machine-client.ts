// Machine-client provisioning primitives (contracts §17.2). Library functions,
// NOT endpoints: machine clients are provisioned OUT-OF-BAND, never via open
// `/oauth/register`. The `/oauth/token` client_credentials grant that CONSUMES
// these records is S3b; S3a ships provisioning + the timing-safe verify primitive.
//
// Secret (§17.2): `mcs_` + base64url(32) = 256 bits. Stored as UNSALTED SHA-256
// hex only (RFC 6819 §5.1.4.1.3 salts LOW-entropy creds; a 256-bit random secret
// needs no salt, and bcrypt on the token hot path is a DoS lever). Comparison is
// constant-time. The raw secret is returned ONCE and never retrievable.

import { randomBytes, timingSafeEqual } from "node:crypto";
import type { ClientStore, ClientSecret, MachineClientRegistration } from "./ports/client-store.ts";
import type { ClockPort } from "./ports/clock.ts";
import type { AuditPort } from "./ports/audit.ts";
import { sha256Hex } from "./crypto.ts";
import { isScopeToken } from "./scopes.ts";
import { OAuthError } from "./errors.ts";

/** Default rotation grace (the two-active-secrets overlap window). 24 h. */
export const DEFAULT_ROTATION_GRACE_SECONDS = 86_400;

/** §17.2: a machine record holds ≤ 2 active secrets. verify caps work here and
 *  fails closed above it. Also the fixed width of verify's comparison loop. */
const MAX_ACTIVE_SECRETS = 2;

/** Never-matching 64-char digest that pads verify's loop to a fixed width. */
const ZERO_HASH = "0".repeat(64);

export interface MachineClientDeps {
  store: ClientStore;
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
    const clientId = mintMachineClientId();
    const clientSecret = mintClientSecret();
    const record: MachineClientRegistration = {
      clientId,
      redirectUris: [],
      applicationType: "machine",
      issuedAtEpoch: now,
      name: input.name,
      allowedScopes,
      // Single active secret. 128-bit id ⇒ collision negligible; a custom
      // ClientStore.save must preserve the ≤2-active invariant.
      secrets: [{
        hash: sha256Hex(clientSecret),
        createdAtEpoch: now,
        expiresAtEpoch: input.secretTtlSeconds !== undefined ? now + input.secretTtlSeconds : undefined,
      }],
    };
    await deps.store.save(record);
    await deps.audit.writeAuthEvent({
      occurredAt: new Date(deps.clock.nowMs()).toISOString(),
      event: "oauth.client.provision", status: "success",
      clientId, scopes: allowedScopes,
    });
    return { clientId, clientSecret };
  } catch (error) {
    await deps.audit.writeAuthEvent({
      occurredAt: new Date(deps.clock.nowMs()).toISOString(),
      event: "oauth.client.provision", status: "failure",
      reason: error instanceof OAuthError ? error.code : "internal_error",
    });
    throw error;
  }
}

/** Rotate a machine client's secret. Demotes the currently-live secret to a
 *  `now + graceSeconds` grace window, adds the new live secret, and trims the
 *  record to exactly the permitted active set (≤ 2 unexpired; exactly one
 *  live). Returns the new secret ONCE. Unknown / non-machine clientId ⇒
 *  `invalid_client`. */
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
    const client = await deps.store.find(clientId);
    if (!client) throw new OAuthError("invalid_client", "Unknown clientId", 401);
    if (client.applicationType !== "machine") throw new OAuthError("invalid_client", "clientId is not a machine client", 401);
    if (!Array.isArray(client.secrets)) throw new OAuthError("invalid_client", "Machine client record is malformed (secrets is not an array)", 401);
    const now = epochSeconds(deps.clock);
    const clientSecret = mintClientSecret();
    const secrets = rotateSecrets(client.secrets, now, graceSeconds, sha256Hex(clientSecret));
    await deps.store.save({ ...client, secrets });
    await deps.audit.writeAuthEvent({
      occurredAt: new Date(deps.clock.nowMs()).toISOString(),
      event: "oauth.client.rotate_secret", status: "success",
      clientId, scopes: client.allowedScopes,
    });
    return { clientSecret };
  } catch (error) {
    await deps.audit.writeAuthEvent({
      occurredAt: new Date(deps.clock.nowMs()).toISOString(),
      event: "oauth.client.rotate_secret", status: "failure",
      clientId,
      reason: error instanceof OAuthError ? error.code : "internal_error",
    });
    throw error;
  }
}

/** Timing-safe verification primitive the §9.4 client_credentials grant (S3b)
 *  composes into client authentication. SHA-256s the presented secret and
 *  constant-time compares it against the active (unexpired) stored hashes.
 *  Uniform-work + fail-closed: the secret is hashed BEFORE the store lookup
 *  (no client-existence oracle); every path runs the SAME fixed two-comparison
 *  loop (no early-return slot signal); a missing/non-machine/malformed record
 *  (the deployer-implemented ClientStore bypasses the type layer at runtime) or
 *  a > 2-active (poisoned) record ⇒ `false`, never thrown. */
export async function verifyMachineClientSecret(
  deps: MachineClientDeps,
  clientId: string,
  presentedSecret: string,
): Promise<boolean> {
  if (typeof presentedSecret !== "string" || presentedSecret.length === 0) return false;
  // Hash FIRST, unconditionally (the caller's own input leaks nothing) so the
  // dominant post-lookup cost is the same for every clientId.
  const presented = sha256Hex(presentedSecret);
  const client = await deps.store.find(clientId);
  const now = epochSeconds(deps.clock);
  // Active = well-formed + unexpired, only for a real machine record. Unknown /
  // non-machine / malformed ⇒ []; > 2 active (poisoned, §17.2) ⇒ [] (fail closed).
  let active: string[] = [];
  if (client?.applicationType === "machine" && Array.isArray(client.secrets)) {
    active = client.secrets
      .filter((s): s is ClientSecret => s !== null && typeof s === "object"
        && typeof s.hash === "string"
        && (s.expiresAtEpoch === undefined || typeof s.expiresAtEpoch === "number"))
      .filter((s) => s.expiresAtEpoch === undefined || s.expiresAtEpoch > now)
      .map((s) => s.hash);
    if (active.length > MAX_ACTIVE_SECRETS) active = [];
  }
  // Fixed two-comparison loop on every path (padded with a never-matching dummy)
  // so timing is independent of active count.
  let matched = false;
  for (let i = 0; i < MAX_ACTIVE_SECRETS; i++) {
    if (timingSafeHexEqual(presented, active[i] ?? ZERO_HASH)) matched = true;
  }
  return matched;
}

/** Pure rotation model (exported for tests): the permitted active set after a
 *  rotation — one NEW live secret plus at most one grace secret. DROP every
 *  already-expired entry first (an expired secret is never demoted back to life
 *  — no resurrection); demote the live (or, if none, newest unexpired) secret to
 *  `now + graceSeconds` (§17.2: "expires the old at now + grace", overriding any
 *  prior expiry); drop all other older entries so ≤ 2 unexpired remain. */
export function rotateSecrets(
  existing: readonly ClientSecret[],
  now: number,
  graceSeconds: number,
  newHash: string,
): ClientSecret[] {
  const unexpired = existing.filter((s) => s.expiresAtEpoch === undefined || s.expiresAtEpoch > now);
  if (unexpired.length === 0) return [{ hash: newHash, createdAtEpoch: now }];
  const demoteSource = unexpired.find((s) => s.expiresAtEpoch === undefined)
    ?? [...unexpired].sort((a, b) => b.createdAtEpoch - a.createdAtEpoch)[0]!;
  return [
    { hash: demoteSource.hash, createdAtEpoch: demoteSource.createdAtEpoch, expiresAtEpoch: now + graceSeconds },
    { hash: newHash, createdAtEpoch: now },
  ];
}

function validateAllowedScopes(input: unknown, catalog: readonly string[]): string[] {
  if (!Array.isArray(input) || input.length === 0) {
    throw new OAuthError("invalid_scope", "allowedScopes must be a non-empty array");
  }
  const allowed = new Set(catalog);
  const out: string[] = [];
  for (const scope of input) {
    if (typeof scope !== "string" || !isScopeToken(scope)) {
      throw new OAuthError("invalid_scope", "allowedScopes entries must be single RFC 6749 scope tokens");
    }
    if (!allowed.has(scope)) {
      throw new OAuthError("invalid_scope", "allowedScopes must be a subset of scopeCatalog");
    }
    if (!out.includes(scope)) out.push(scope);
  }
  return out;
}

function timingSafeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function isPositiveInteger(value: number): boolean {
  return Number.isInteger(value) && value > 0;
}

function epochSeconds(clock: ClockPort): number {
  return Math.floor(clock.nowMs() / 1000);
}

function mintMachineClientId(): string { return `mcc_${randomBytes(16).toString("base64url")}`; }
function mintClientSecret(): string { return `mcs_${randomBytes(32).toString("base64url")}`; }
