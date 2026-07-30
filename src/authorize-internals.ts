// Helpers for `OAuthAuthorizationUseCase` (authorize.ts), factored out so the
// use-case stays under the 250-line file limit (contracts §6). This module owns
// the §17.1.6 decision-1a shape-first dispatch, the decision-3 accumulation and
// approve-time gates, and the consent display projection — plus the small pure
// helpers the use-case already had.

import type { AnyBridgeConfig as BridgeConfig } from "./config.ts";
import { originOf } from "./config.ts";
import { OAuthError } from "./errors.ts";
import { assertAllowedRedirectUri, assertRedirectAllowedForClient } from "./redirect.ts";
import type { CimdResolver } from "./cimd/resolve.ts";
import { cimdGenericError } from "./cimd/resolve.ts";
import {
  cimdRedirectMatches, displayHost, everyRedirectIsLoopback, isCimdClientId,
  isSchemeShaped, type CimdRegistration,
} from "./cimd/registration.ts";
import { buildResourceCatalog, resolveResource } from "./resource.ts";
import type { ResourceCatalog, ResourceConfiguration } from "./resource.ts";
import type { ResourceBindingExpectation, StorePort } from "./ports/store.ts";
import { assertStoredDcrGenerationStore } from "./stored-dcr-generation.ts";

export { resolveResource };
export type { ResourceCatalog };

/** Display-only CIMD fields handed to the consent renderer (§17.1.6 decision
 *  1c / §17.1.4). `clientName` is UNVERIFIED text — the renderer escapes it. */
export interface CimdConsentDisplay {
  readonly clientIdHost: string;
  readonly redirectHost: string;
  readonly clientName: string;
  readonly allRedirectsLoopback: boolean;
}

export interface ResolvedAuthorizeClient {
  readonly redirectUri: string;
  readonly registration?: CimdRegistration;
  /** Emits the deferred `oauth.cimd.fetch` success event (no-op otherwise). */
  emitCimdSuccess(): Promise<void>;
}

/** Shape-first three-way dispatch (§17.1.6 decision 1a), identical at BOTH the
 *  upstream authorize resolve and `prepare`'s `resolveRedirect`:
 *    (1) literal-lowercase `https://` + `cimd` enabled → the CIMD path, which
 *        REPLACES §10 (the stored-mode `store.find` miss MUST NOT fire);
 *    (2) ANY other scheme-shaped value, and lowercase-`https://` while CIMD is
 *        disabled → direct `invalid_client`, never a stateless fallback;
 *    (3) an opaque non-scheme id → the unchanged §10 path.
 *  A supplied `registration` (carried forward by the upstream orchestrator)
 *  suppresses the fetch — the switch is registration-PRESENCE, not mode — and
 *  gets `prepare`'s defensive redirect re-check, which throws a DIRECT
 *  `invalid_client` and never a 302. */
export async function resolveAuthorizeClient(args: {
  config: BridgeConfig;
  cimd?: CimdResolver;
  clientId: string;
  redirectUri: string;
  registration?: CimdRegistration;
  ip?: string;
}): Promise<ResolvedAuthorizeClient> {
  const { config, clientId, redirectUri } = args;
  const noop = async (): Promise<void> => { /* nothing resolved this request */ };
  if (args.registration !== undefined) {
    // Defense-in-depth (1d): an internally-inconsistent signed cookie makes
    // `params.redirect_uri` untrusted ⇒ direct, never a redirect-channel error.
    // The id binding is re-checked here too: `prepare` is exported, and minting
    // `cimd_verified` for a client_id whose document was never validated would
    // be the one consequence of a mismatch. (The orchestrator already binds
    // them at flow-token parse; this is the same check at the second seam.)
    if (args.registration.client_id !== clientId) throw cimdGenericError();
    if (!cimdRedirectMatches(redirectUri, args.registration.redirect_uris)) throw cimdGenericError();
    return { redirectUri, registration: args.registration, emitCimdSuccess: noop };
  }
  if (isCimdClientId(clientId)) {
    if (config.cimd?.enabled !== true || args.cimd === undefined) throw cimdGenericError();
    const resolution = await args.cimd.resolve({ clientId, redirectUri, ip: args.ip });
    return { redirectUri, registration: resolution.registration, emitCimdSuccess: () => resolution.emitSuccess() };
  }
  if (isSchemeShaped(clientId)) throw cimdGenericError();
  return { redirectUri: await resolveOpaqueRedirect(config, clientId, redirectUri), emitCimdSuccess: noop };
}

/** The unchanged §10 path for an opaque client_id. Stored mode applies the
 *  per-client policy (§10.2); stateless applies the global allowlist (§10.1). */
export async function resolveOpaqueRedirect(config: BridgeConfig, clientId: string, redirectUri: string): Promise<string> {
  if (config.dcr.mode === "stored") {
    const client = await config.dcr.store.find(clientId);
    if (!client) throw new OAuthError("invalid_client", "Unknown client_id", 401);
    return assertRedirectAllowedForClient(redirectUri, client);
  }
  return assertAllowedRedirectUri(redirectUri, config.redirectAllowlist);
}

/** §17.1.6 decision 3, the NEGATIVE class: accumulation runs iff stored-DCR AND
 *  NOT scheme-shaped. Never keyed on `startsWith("https://")`, never on
 *  `cimd_verified` — so a mis-propagated provenance bit can never enable a
 *  grant-store read. */
export function accumulationAllowed(config: BridgeConfig, clientId: string): boolean {
  return config.dcr.mode === "stored" && !isSchemeShaped(clientId);
}

/** Approve-time scheme/claim consistency gate (§17.1.6 decision 3) — a validity
 *  check, NOT an accumulation decision. Runs immediately after
 *  `verifyConsentToken` and BEFORE the Deny branch, the jti consume, and any
 *  code storage, so a legacy URL-shaped token cannot even be Deny-redirected. */
export function assertApproveCimdGate(config: BridgeConfig, clientId: string, cimdVerified: true | undefined): void {
  const enabled = config.cimd?.enabled === true;
  if (isCimdClientId(clientId)) {
    if (!enabled || cimdVerified !== true) throw invalidConsent();
    return;
  }
  if (isSchemeShaped(clientId)) throw invalidConsent();
  if (cimdVerified === true) throw invalidConsent(); // provenance bit on a non-CIMD id
}

function invalidConsent(): OAuthError {
  return new OAuthError("invalid_consent", "Consent token is invalid or expired");
}

export function cimdDisplay(registration: CimdRegistration, redirectUri: string): CimdConsentDisplay {
  return {
    clientIdHost: displayHost(registration.client_id),
    redirectHost: displayHost(redirectUri),
    clientName: registration.client_name,
    allRedirectsLoopback: everyRedirectIsLoopback(registration.redirect_uris),
  };
}

/** CSRF/Origin check for `approve` (§9.3): the Origin must be the issuer
 *  origin or in `allowedOrigins` — a foreign origin is never redirected
 *  anywhere (direct `invalid_origin` 403). */
export function assertApproveOrigin(config: BridgeConfig, origin: string | undefined): void {
  const issuerOrigin = originOf(config.issuer);
  if (!origin || (!config.allowedOrigins.includes(origin) && origin !== issuerOrigin)) {
    throw new OAuthError("invalid_origin", "Origin not allowed", 403);
  }
}

export function redirectWithCode(redirectUri: string, code: string, issuer: string, state?: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set("code", code);
  url.searchParams.set("iss", issuer); // RFC 9207 (RC item a)
  if (state) url.searchParams.set("state", state);
  url.hash = "";
  return url.href;
}

export function hostOf(value: string): string | undefined {
  try {
    const u = new URL(value);
    return `${u.protocol}//${u.host}`;
  } catch {
    return undefined;
  }
}

export function dedupe(values: string[]): string[] {
  const out: string[] = [];
  for (const v of values) if (!out.includes(v)) out.push(v);
  return out;
}

export function requiredStr(value: string | undefined, label: string): string {
  if (typeof value === "string" && value) return value;
  throw new OAuthError("invalid_request", `${label} is required`);
}

/** Build the immutable catalog once at construction and assert the store
 *  capability in the same step (both are boot-time guards). */
export function initAuthorizeCatalog(config: BridgeConfig, store: StorePort): ResourceCatalog {
  assertStoredDcrGenerationStore(config, store);
  return buildResourceCatalog(
    config as unknown as ResourceConfiguration,
    { allowInsecureLocalhost: config.dev?.allowInsecureLocalhost === true },
  );
}

/** The resource-binding expectation passed to findGrantedScopes: the resolved
 *  resource string plus legacy-singleton binding (one catalog entry ⇒ a null
 *  pre-0.4 prior grant can only be from this resource). A prior grant for
 *  resource A is never evidence for B (§9.7). */
export function authorizeBinding(catalog: ResourceCatalog, resource: string): ResourceBindingExpectation {
  return { resource, allowLegacySingletonBinding: catalog.entries.length === 1 };
}

/** Approval re-resolves the signed consent resource against the CURRENT catalog
 *  before saving a code (§9.7). A removed resource is invalid_target; a scope no
 *  longer in that resource's catalog is invalid_scope. Neither saves a code. */
export function assertConsentResourceCurrent(catalog: ResourceCatalog, resource: string, scopes: readonly string[]): void {
  const resolved = resolveResource(catalog, resource);
  for (const scope of scopes) {
    if (!resolved.scopeCatalog.includes(scope)) {
      throw new OAuthError("invalid_scope", "A consent scope is no longer in the resource catalog");
    }
  }
}
