// EntraIdentity — the bridge acts as an OIDC client to Microsoft Entra ID v2.0:
// it redirects the user to Entra (auth-code + PKCE), exchanges the code for an
// id_token, validates iss/aud/tid, and maps oid/email → subject. The bridge then
// issues its OWN audience-bound tokens (no Entra token passthrough).
//
// Entra's endpoints are always the well-known https login.microsoftonline.com URLs
// (raw `^https://` asserted, addendum 11). Claim validation is exported and unit-
// testable WITHOUT the JWKS fetch (addendum 12); code exchange takes an injectable
// transport so it is testable without the network. An optional subject/email
// allowlist adds defense-in-depth.
//
// --- Manual live-tenant verification (run before claiming Entra works end-to-end;
// full walkthrough + setup in docs/identity/entra.md) ---
//   1. Register one app (redirect URI = the bridge callback; public-client PKCE or a secret).
//   2. Sign a real user in; confirm the bridge mints its OWN token (Entra token never forwarded).
//   3. Confirm the deny legs: wrong tenant (entra_bad_tid / entra_bad_iss), group overage
//      >200 (entra_groups_overage — the `_claim_sources` URL is NEVER fetched), no-mapped-groups
//      (entra_no_mapped_groups). groupAuthorization keys MUST be group object-ID GUIDs, never
//      display names (spoof vector). Guest/B2B group behavior is unverified — check before relying on it.

import { errors, jwtVerify } from "jose";
import type { IdentityClaims, IdentityResult } from "../ports/identity.ts";
import { type GroupAuthorization, resolveGroupCeiling } from "./entra-groups.ts";
import { assertHttpsRaw, captureHttpResponse } from "./util.ts";
import { AuthConfigError } from "../config.ts";
import {
  bindClassDataMethod, ownBooleanTrue, snapshotOwnDataRecord, snapshotOwnStringArray,
} from "../own-property.ts";
import {
  createValidatedRemoteJWKSet, isRemoteJwksInfrastructureError,
} from "./remote-jwks.ts";
import { snapshotEntraConfig } from "./entra-config.ts";
import type {
  EntraAuthorizeRequest, EntraConfig, EntraIdentity, EntraPayload,
  EntraTokenTransport, EntraVerifyKey, EntraVerifyOptions,
} from "./entra-types.ts";

export type {
  EntraAuthorizeRequest, EntraConfig, EntraIdentity, EntraTokenTransport,
  EntraVerifyKey, EntraVerifyOptions,
} from "./entra-types.ts";

const ENTRA_BASE = "https://login.microsoftonline.com";

export function entraIssuer(tenantId: string): string { return `${ENTRA_BASE}/${tenantId}/v2.0`; }
export function entraAuthorizeEndpoint(tenantId: string): string { return `${ENTRA_BASE}/${tenantId}/oauth2/v2.0/authorize`; }
export function entraTokenEndpoint(tenantId: string): string { return `${ENTRA_BASE}/${tenantId}/oauth2/v2.0/token`; }
export function entraJwksUrl(tenantId: string): string { return `${ENTRA_BASE}/${tenantId}/discovery/v2.0/keys`; }

/** Build the Entra v2.0 authorization URL (auth-code + PKCE S256). */
export function getAuthorizationUrl(config: EntraConfig, req: EntraAuthorizeRequest): string {
  const safeConfig = snapshotEntraConfig(config);
  const fields = snapshotOwnDataRecord(req);
  if (fields === null || typeof fields.state !== "string" || !fields.state
    || typeof fields.codeChallenge !== "string" || !fields.codeChallenge) {
    throw new Error("entra_bad_config: authorization request is malformed");
  }
  if (fields.codeChallengeMethod !== undefined && fields.codeChallengeMethod !== "S256") throw new Error("entra_bad_config: codeChallengeMethod must be S256 (PKCE plain/other rejected — sibling of generic-oidc)");
  const params = new URLSearchParams({
    client_id: safeConfig.clientId,
    response_type: "code",
    redirect_uri: safeConfig.redirectUri,
    response_mode: "query",
    scope: typeof fields.scope === "string" ? fields.scope : "openid profile email offline_access",
    state: fields.state,
    code_challenge: fields.codeChallenge,
    code_challenge_method: fields.codeChallengeMethod as "S256" | undefined ?? "S256",
    ...(typeof fields.nonce === "string" && fields.nonce ? { nonce: fields.nonce } : {}),
  });
  return `${entraAuthorizeEndpoint(safeConfig.tenantId)}?${params.toString()}`;
}

export async function exchangeCodeForToken(
  config: EntraConfig,
  args: { code: string; codeVerifier: string },
  transport: EntraTokenTransport,
): Promise<string> {
  const safeConfig = snapshotEntraConfig(config);
  const fields = snapshotOwnDataRecord(args);
  if (fields === null || typeof fields.code !== "string" || !fields.code
    || typeof fields.codeVerifier !== "string" || !fields.codeVerifier) {
    throw new Error("entra token exchange input is malformed");
  }
  const body = new URLSearchParams({
    client_id: safeConfig.clientId,
    grant_type: "authorization_code",
    code: fields.code,
    redirect_uri: safeConfig.redirectUri,
    code_verifier: fields.codeVerifier,
    ...(safeConfig.clientSecret ? { client_secret: safeConfig.clientSecret } : { scope: "openid profile email" }),
  });
  const postForm = bindClassDataMethod<EntraTokenTransport["postForm"]>(transport, "postForm");
  if (postForm === undefined) throw new Error("entra token transport is malformed");
  const response = captureHttpResponse(
    await postForm(entraTokenEndpoint(safeConfig.tenantId), body), "text",
  );
  if (response === null) throw new Error("entra token exchange returned a malformed response");
  if (response.status !== 200) { let detail = ""; try { const text = await response.read(); if (typeof text !== "string") throw new Error("malformed response body"); const e = snapshotOwnDataRecord(JSON.parse(text)); if (e && typeof e.error === "string") detail = `: ${e.error}${typeof e.error_description === "string" ? ` — ${e.error_description.replace(/[\r\n]+/g, " ")}` : ""}`; } catch { /* non-JSON error body — the HTTP status is the detail */ } throw new Error(`entra token exchange failed: HTTP ${response.status}${detail}`); }
  const text = await response.read();
  const parsed = typeof text === "string" ? snapshotOwnDataRecord(JSON.parse(text)) : null;
  if (parsed === null || typeof parsed.id_token !== "string" || !parsed.id_token) {
    throw new Error("entra token exchange returned no id_token");
  }
  return parsed.id_token;
}

/** Validate an Entra id_token's claims and extract the subject. Exported so the gate
 *  is unit-testable WITHOUT the JWKS fetch. Signature is checked separately by
 *  jwtVerify in the caller. Multi-tenant: when `allowedTenantIds` is set, the `tid`
 *  must be allowlisted AND `iss` must equal `entraIssuer(payload.tid)` (the standard
 *  Entra multi-tenant issuer pattern). Single-tenant (unset): `iss` must equal
 *  `entraIssuer(config.tenantId)` exactly. */
export function validateEntraIdToken(payload: EntraPayload, config: EntraConfig, expectedNonce?: string): { ok: true; identity: IdentityClaims } | { ok: false; reason: string } {
  const payloadSnapshot = snapshotOwnDataRecord(payload);
  let safeConfig: Readonly<EntraConfig>;
  try { safeConfig = snapshotEntraConfig(config); } catch { return { ok: false, reason: "entra_bad_claim" }; }
  if (payloadSnapshot === null) return { ok: false, reason: "entra_bad_claim" };
  const claimsPayload = payloadSnapshot as EntraPayload;
  if (safeConfig.allowedTenantIds && safeConfig.allowedTenantIds.length > 0) {
    if (!claimsPayload.tid || !safeConfig.allowedTenantIds.includes(claimsPayload.tid)) return { ok: false, reason: "entra_bad_tid" };
    if (claimsPayload.iss !== entraIssuer(claimsPayload.tid)) return { ok: false, reason: "entra_bad_iss" };
  } else {
    if (claimsPayload.iss !== entraIssuer(safeConfig.tenantId)) return { ok: false, reason: "entra_bad_iss" };
    if (claimsPayload.tid && claimsPayload.tid !== safeConfig.tenantId) return { ok: false, reason: "entra_bad_tid" };
  }
  if (claimsPayload.aud !== safeConfig.clientId) return { ok: false, reason: "entra_bad_aud" };
  if (expectedNonce !== undefined && claimsPayload.nonce !== expectedNonce) return { ok: false, reason: "entra_bad_nonce" };
  if (!claimsPayload.exp) return { ok: false, reason: "entra_missing_exp" };
  for (const key of ["oid", "preferred_username", "email"] as const) {
    if (claimsPayload[key] !== undefined && typeof claimsPayload[key] !== "string") {
      return { ok: false, reason: "entra_bad_claim" };
    }
  }
  const subject = [claimsPayload.oid, claimsPayload.preferred_username, claimsPayload.email]
    .find((value): value is string => typeof value === "string" && value.length > 0);
  if (!subject) return { ok: false, reason: "entra_no_subject" };
  if (safeConfig.subjectAllowlist && safeConfig.subjectAllowlist.length > 0
    && !subjectAllowed(claimsPayload, safeConfig.subjectAllowlist, ownBooleanTrue(safeConfig, "allowMutableClaims"))) {
    return { ok: false, reason: "entra_subject_not_allowed" };
  }
  const claims = { oid: claimsPayload.oid, email: claimsPayload.email ?? claimsPayload.preferred_username,
    tid: claimsPayload.tid, expiresAt: claimsPayload.exp };
  // §17.4: when group→scope mapping is configured, resolve the ceiling from the
  // VERIFIED payload (signature already checked by the caller). Unconfigured ⇒
  // unchanged v0.1 behavior (no ceiling). Overage/no-groups fail CLOSED here so
  // the bridge's resolveIdentity emits identity.verify with the Entra reason.
  if (safeConfig.groupAuthorization) {
    const ceiling = resolveGroupCeiling(claimsPayload, safeConfig.groupAuthorization);
    if (!ceiling.ok) return ceiling; // entra_groups_overage | entra_no_groups
    return { ok: true, identity: { subject, allowedScopes: ceiling.allowedScopes, claims } };
  }
  return { ok: true, identity: { subject, claims } };
}

/** Case-insensitive allowlist match. Matches the immutable `oid` by default; only
 *  matches the mutable preferred_username/email when `allowMutable` is true
 *  (Microsoft warns against using those claims for authorization). */
export function subjectAllowed(payload: EntraPayload, allowlist: string[], allowMutable = false): boolean {
  const payloadSnapshot = snapshotOwnDataRecord(payload);
  const entries = snapshotOwnStringArray(allowlist);
  if (payloadSnapshot === null || entries === null) return false;
  const claims = payloadSnapshot as EntraPayload;
  const candidates: string[] = [];
  if (typeof claims.oid === "string" && claims.oid) candidates.push(claims.oid);
  if (allowMutable === true) {
    if (typeof claims.preferred_username === "string" && claims.preferred_username) {
      candidates.push(claims.preferred_username);
    }
    if (typeof claims.email === "string" && claims.email) candidates.push(claims.email);
  }
  return candidates.some((c) => entries.some((entry) => entry.trim().toLowerCase() === c.trim().toLowerCase()));
}

/** Verify an Entra id_token against an explicit key (CryptoKey/Uint8Array). Exported
 *  so the full path is testable with a known key — no JWKS fetch. */
export async function verifyEntraIdToken(token: string, key: EntraVerifyKey, config: EntraConfig, options?: EntraVerifyOptions): Promise<IdentityResult> {
  try {
    const optionSnapshot = options === undefined ? undefined : snapshotOwnDataRecord(options);
    if (optionSnapshot === null) return { ok: false, reason: "entra_bad_claim" };
    const { payload } = await jwtVerify<EntraPayload>(token, key, {
      algorithms: ["RS256"], currentDate: optionSnapshot?.currentDate as Date | undefined,
    });
    return validateEntraIdToken(payload, config, optionSnapshot?.expectedNonce as string | undefined);
  } catch (error) {
    return { ok: false, reason: jwtErrorReason(error) };
  }
}

/** Build the Entra identity port. `verify` takes a raw id_token string; the adapter
 *  drives getAuthorizationUrl + exchangeCodeForToken for the redirect dance.
 *  `opts.scopeCatalog` is the wiring-time junction where the Entra group mapping
 *  and the bridge catalog meet: when supplied, the mapped/base scopes are
 *  validated ⊆ scopeCatalog at boot (§17.4). Omit it only if the deployer
 *  validates the subset elsewhere — passing it is recommended. */
export function createEntraIdentity(config: EntraConfig, opts?: { scopeCatalog?: readonly string[] }): EntraIdentity {
  const optionSnapshot = opts === undefined ? undefined : snapshotOwnDataRecord(opts);
  if (optionSnapshot === null) throw new AuthConfigError("Entra options must be a data object");
  const safeConfig = snapshotEntraConfig(config,
    optionSnapshot?.scopeCatalog as readonly string[] | undefined);
  assertHttpsRaw(ENTRA_BASE, "entra base");
  // Fail closed on blank required config (empty == missing) — sibling of the CF
  // empty-audience guard: a blank tenantId/clientId builds malformed URLs / a vacuous aud check.
  const jwks = createValidatedRemoteJWKSet(new URL(entraJwksUrl(safeConfig.tenantId)), { cacheMaxAge: 5 * 60 * 1000 });
  return {
    getAuthorizationUrl: (req) => getAuthorizationUrl(safeConfig, req),
    exchangeCodeForToken: (args, transport) => exchangeCodeForToken(safeConfig, args, transport),
    async verify(input: unknown, options?: { expectedNonce?: string }): Promise<IdentityResult> {
      if (typeof input !== "string" || !input) return { ok: false, reason: "entra_id_token_missing" };
      try {
        const verifySnapshot = options === undefined ? undefined : snapshotOwnDataRecord(options);
        if (verifySnapshot === null) return { ok: false, reason: "entra_bad_claim" };
        const { payload } = await jwtVerify<EntraPayload>(input, jwks, { algorithms: ["RS256"] });
        return validateEntraIdToken(payload, safeConfig,
          verifySnapshot?.expectedNonce as string | undefined);
      } catch (error) {
        return { ok: false, reason: jwtErrorReason(error) };
      }
    },
  };
}
function jwtErrorReason(error: unknown): string {
  if (error instanceof errors.JWTExpired) return "entra_token_expired";
  if (error instanceof errors.JWTClaimValidationFailed) return "entra_bad_claim";
  if (error instanceof errors.JOSEAlgNotAllowed) return "entra_unsupported_alg";
  // A remote key-source timeout or malformed response means no identity
  // decision was possible. Key-selection misses remain identity denials.
  if (isRemoteJwksInfrastructureError(error)) return "entra_verify_failed";
  if (error instanceof errors.JWKSNoMatchingKey) return "entra_unknown_key";
  if (error instanceof errors.JOSEError) return "entra_token_invalid";
  return "entra_verify_failed";
}

// Public group-authorization API (§17.4) re-exported for the ./identity/entra subpath.
export { type GroupAuthorization, assertGroupAuthorizationMapping, resolveGroupCeiling } from "./entra-groups.ts";
// §17.11 redirect-flow identity (createEntraRedirectIdentity) re-exported for the ./identity/entra subpath.
export { createEntraRedirectIdentity, type EntraRedirectOptions } from "./entra-redirect.ts";
